#include <string.h>

#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>

#define LOG_TAG "handshake"
#include <dslink/log.h>
#include <dslink/handshake.h>
#include <dslink/utils.h>

#include "broker/remote_dslink.h"
#include "broker/handshake.h"
#include "broker/node.h"

json_t *broker_handshake_handle_conn(Broker *broker,
                                     const char *dsId,
                                     json_t *handshake) {
    if (dslink_map_contains(&broker->client_connecting, (void *) dsId)) {
        return NULL;
    }

    RemoteDSLink *link = calloc(1, sizeof(RemoteDSLink));
    json_t *resp = json_object();
    if (!(link && resp)) {
        goto fail;
    }
    link->auth = calloc(1, sizeof(RemoteAuth));
    if (!link->auth) {
        goto fail;
    }

    if (dslink_handshake_generate_key_pair(&link->auth->tempKey) != 0) {
        log_err("Failed to create temporary key for DSLink\n");
        goto fail;
    }

    {
        json_t *jsonPubKey = json_object_get(handshake, "publicKey");
        if (!jsonPubKey) {
            goto fail;
        }

        const char *tmp = json_string_value(jsonPubKey);
        if (!tmp) {
            goto fail;
        }
        tmp = dslink_strdup(tmp);
        if (!tmp) {
            goto fail;
        }
        link->auth->pubKey = tmp;
    }

    char tempKey[90];
    size_t tempKeyLen = 0;
    if (dslink_handshake_encode_pub_key(&link->auth->tempKey, tempKey,
                                        sizeof(tempKey), &tempKeyLen) != 0) {
        goto fail;
    }

    {
        unsigned char buf[32];
        mbedtls_entropy_context ent;
        mbedtls_entropy_init(&ent);
        if (mbedtls_entropy_func(&ent, buf,
                                 sizeof(buf)) != 0) {
            mbedtls_entropy_free(&ent);
            goto fail;
        }
        mbedtls_entropy_free(&ent);

        size_t len = 0;
        if (mbedtls_base64_encode((unsigned char *) link->auth->salt,
                                  sizeof(link->auth->salt), &len,
                                  buf, sizeof(buf)) != 0) {
            goto fail;
        }
    }

    json_object_set_new_nocheck(resp, "wsUri", json_string("/ws"));
    json_object_set_new_nocheck(resp, "tempKey", json_string(tempKey));
    json_object_set_new_nocheck(resp, "salt", json_string(link->auth->salt));
    if (json_boolean_value(json_object_get(handshake, "isResponder"))) {
        link->isResponder = 1;

        size_t dsIdLen = strlen(dsId);
        if (dsIdLen < 44) {
            goto fail;
        }
        size_t nameLen = dsIdLen - 43;
        {
            if (dsId[nameLen - 1] == '-') {
                nameLen--;
            }
        }

        char buf[512];
        int len = snprintf(buf, sizeof(buf), "/downstream/%.*s",
                              (int) nameLen, dsId);
        buf[len] = '\0';
        link->name = dslink_strdup(buf);
        if (!link->name) {
            goto fail;
        }
        json_object_set_new_nocheck(resp, "path", json_string(buf));
    }

    if (json_boolean_value(json_object_get(handshake, "isRequester"))) {
        link->isRequester = 1;
    }

    {
        char *tmp = dslink_strdup(dsId);
        if (!tmp) {
            goto fail;
        }
        void *value = (void *) link;
        if (dslink_map_set(&broker->client_connecting, tmp, &value) != 0) {
            free(tmp);
            goto fail;
        }
    }

    return resp;
fail:
    if (link) {
        broker_remote_dslink_free(link);
        free((void *) link->name);
        free(link);
    }
    DSLINK_CHECKED_EXEC(json_decref, resp);
    return NULL;
}

int broker_handshake_handle_ws(Broker *broker,
                               const char *dsId,
                               const char *auth,
                               void **socketData) {
    void *oldDsId = (void *) dsId;
    RemoteDSLink *link = dslink_map_remove(&broker->client_connecting,
                                           &oldDsId);
    if (!(link && auth && link->auth->pubKey)) {
        return 1;
    }

    int ret = 0;
    { // Perform auth check
        char expectedAuth[90];
        if (dslink_handshake_gen_auth_key(&link->auth->tempKey,
                                          link->auth->pubKey,
                                          link->auth->salt,
                                          (unsigned char *) expectedAuth,
                                          sizeof(expectedAuth)) != 0) {
            ret = 1;
            goto exit;
        }

        if (strcmp(expectedAuth, auth) != 0) {
            ret = 1;
            goto exit;
        }
    }

    DownstreamNode *node = NULL;
    { // Handle retrieval of the downstream node
        node = dslink_map_get(&broker->downstream, (void *) link->name);
        if (!node) {
            node = calloc(1, sizeof(DownstreamNode));
            if (!node) {
                ret = 1;
                goto exit;
            }
            void *tmp = (void *) node;
            if (dslink_map_set(&broker->downstream,
                               (void *) link->name, &tmp) != 0) {
                free(node);
                free(oldDsId);
                ret = 1;
                goto exit;
            }
        } else {
            // Data is already stored in the downstream node
            // free up this data and move on
            free((void *) link->name);
            free(oldDsId);
            oldDsId = (void *) node->dsId;
        }
    }

    link->dsId = oldDsId;
    link->node = node;

    node->link = link;
    node->dsId = oldDsId;
    node->name = link->name;

    *socketData = link;
    log_info("DSLink `%s` has connected\n", dsId);
exit:
    mbedtls_ecdh_free(&link->auth->tempKey);
    free((void *) link->auth->pubKey);
    free(link->auth);
    link->auth = NULL;
    if (ret != 0) {
        free(link);
    }
    return ret;
}
