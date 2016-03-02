#include <string.h>

#include <mbedtls/entropy.h>
#include <mbedtls/base64.h>

#define LOG_TAG "handshake"
#include <dslink/log.h>
#include <dslink/handshake.h>
#include <dslink/utils.h>
#include <dslink/mem/mem.h>
#include "broker/msg/msg_list.h"
#include "broker/handshake.h"

static
DownstreamNode *broker_init_downstream_node(Broker *broker, const char *name) {
    DownstreamNode *node = dslink_calloc(1, sizeof(DownstreamNode));
    if (!node) {
        return NULL;
    }
    node->type = DOWNSTREAM_NODE;
    if (dslink_map_init(&node->sub_sids, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal) != 0
        || dslink_map_init(&node->sub_paths, dslink_map_str_cmp,
                           dslink_map_str_key_len_cal) != 0
        || dslink_map_init(&node->local_subs, dslink_map_str_cmp,
                           dslink_map_str_key_len_cal) != 0
        || dslink_map_init(&node->list_streams, dslink_map_str_cmp,
                           dslink_map_str_key_len_cal) != 0) {
        goto fail;
    }

    node->name = dslink_strdup(name);
    node->meta = json_object();
    if (!(node->name
          && node->meta
          && json_object_set_new_nocheck(node->meta, "$is",
                                         json_string_nocheck("node")) == 0)) {
        goto fail;
    }

    char *tmpKey = dslink_strdup(name);
    if (!tmpKey) {
        goto fail;
    }
    if (dslink_map_set(broker->downstream->children,
                       dslink_ref(tmpKey, dslink_free),
                       dslink_ref(node, NULL)) != 0) {
        dslink_free(tmpKey);
        goto fail;
    }
    return node;

fail:
    dslink_map_free(&node->sub_sids);
    dslink_map_free(&node->sub_paths);
    dslink_map_free(&node->local_subs);
    dslink_map_free(&node->list_streams);

    DSLINK_CHECKED_EXEC(dslink_free, (char *) node->name);
    json_decref(node->meta);
    dslink_free(node);
    return NULL;
}

json_t *broker_handshake_handle_conn(Broker *broker,
                                     const char *dsId,
                                     json_t *handshake) {
    if (dslink_map_contains(&broker->client_connecting, (void *) dsId)) {
        ref_t *ref = dslink_map_remove_get(&broker->client_connecting,
                                           (void *) dsId);
        RemoteDSLink *link = ref->data;
        dslink_map_remove(&broker->client_connecting,
                          (void *) link->name);
        broker_remote_dslink_free(link);
        dslink_free(link);
        dslink_decref(ref);
    }

    RemoteDSLink *link = dslink_calloc(1, sizeof(RemoteDSLink));
    json_t *resp = json_object();
    if (!(link && resp)) {
        goto fail;
    }

    if (broker_remote_dslink_init(link) != 0) {
        goto fail;
    }

    link->broker = broker;
    link->auth = dslink_calloc(1, sizeof(RemoteAuth));
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
    }

    if (json_boolean_value(json_object_get(handshake, "isRequester"))) {
        link->isRequester = 1;
    }

    json_t *linkData = json_object_get(handshake, "linkData");
    if (json_is_object(linkData)) {
        json_incref(linkData);
        link->linkData = linkData;
    }

    {
        char buf[512] = {0};
        snprintf(buf, sizeof(buf), "/downstream/");
        char *name = buf + sizeof("/downstream/")-1;

        size_t dsIdLen = strlen(dsId);
        if (dsIdLen < 44) {
            goto fail;
        }
        size_t nameLen = dsIdLen - 43;
        if (dsId[nameLen - 1] == '-') {
            nameLen--;
        }
        // find a valid name from broker->client_names
        memcpy(name, dsId, nameLen);
        while (1) {
            // TODO: what if it's all conflicted with exiting dslink?
            // is this error handled already

            if (dslink_map_contains(&broker->client_connecting, name)) {
                name[nameLen] = dsId[nameLen];
                nameLen++;
                continue;
            }
            ref_t *ref = dslink_map_get(broker->downstream->children,
                                                  (void *) name);
            if (ref == NULL
                || strcmp(dsId, ((DownstreamNode *) ref->data)->dsId->data) == 0) {
                break;
            }
            name[nameLen] = dsId[nameLen];
            nameLen++;
        }

        json_object_set_new_nocheck(resp, "path", json_string(buf));

        link->path = dslink_strdup(buf);
        if (!link->path) {
            goto fail;
        }
        link->name = link->path + sizeof("/downstream/") - 1;

        // add to connecting map with the name
        if (dslink_map_set(&broker->client_connecting,
                           dslink_ref((void *) link->name, NULL),
                           dslink_ref(link, NULL)) != 0) {
            dslink_free((void *) link->path);
            goto fail;
        }
    }

    {
        ref_t *tmp = dslink_ref(dslink_strdup(dsId), dslink_free);
        if (!tmp) {
            goto fail;
        }
        // add to connecting map with dsId
        if (dslink_map_set(&broker->client_connecting, tmp,
                           dslink_ref(link, NULL)) != 0) {
            dslink_free(tmp);
            goto fail;
        }
    }

    return resp;
fail:
    if (link) {
        broker_remote_dslink_free(link);
        dslink_free((void *) link->path);
        dslink_free(link);
    }
    DSLINK_CHECKED_EXEC(json_decref, resp);
    return NULL;
}

int broker_handshake_handle_ws(Broker *broker,
                               Client *client,
                               const char *dsId,
                               const char *auth,
                               const struct wslay_event_callbacks *cb,
                               const char *wsAccept) {
    ref_t *oldDsId = NULL;
    ref_t *ref = dslink_map_remove_get(&broker->client_connecting,
                                       (char *) dsId);
    if (!ref) {
        return 1;
    }
    RemoteDSLink *link = ref->data;
    dslink_decref(ref);
    if (link->name) {
        dslink_map_remove(&broker->client_connecting,
                          (char *) link->name);
    }
    if (!(auth && link->auth->pubKey)) {
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
        ref = dslink_map_get(broker->downstream->children,
                                    (char *) link->name);
        if (!ref) {
            node = broker_init_downstream_node(broker, link->name);
            if (!node) {
                ret = 1;
                goto exit;
            }
            oldDsId = dslink_ref(dslink_strdup(dsId), dslink_free);
            if (broker->downstream->list_stream) {
                update_list_child(broker->downstream,
                                  broker->downstream->list_stream,
                                  link->name);
            }
        } else {
            node = ref->data;
            oldDsId = node->dsId;
        }
    }

    link->client = client;
    link->dsId = oldDsId;
    link->node = node;
    node->dsId = oldDsId;
    client->sock_data = link;

    wslay_event_context_ptr ws;
    if (wslay_event_context_server_init(&ws, cb, link) != 0) {
        ret = 1;
        goto exit;
    }
    link->ws = ws;
    broker_send_ws_init(client->sock, wsAccept);

    // set the ->link and update all existing stream
    broker_dslink_connect(node, link);
    log_info("DSLink `%s` has connected\n", dsId);
exit:
    mbedtls_ecdh_free(&link->auth->tempKey);
    dslink_free((void *) link->auth->pubKey);
    dslink_free(link->auth);
    link->auth = NULL;
    if (ret != 0) {
        dslink_map_free(&link->requester_streams);
        dslink_map_free(&link->responder_streams);
        dslink_free((char *)link->path);
        dslink_free(link);
    }
    return ret;
}
