#include <errno.h>
#include <string.h>
#include <dslink/crypto.h>

#include "dslink/crypto.h"
#include "dslink/base64_url.h"
#include "dslink/handshake.h"
#include "dslink/err.h"
#include "dslink/utils.h"

#define DSLINK_POST_REQ \
    "POST %s HTTP/1.1\r\n" \
    "Host: %s:%d\r\n" \
    "Content-Length: %d\r\n\r\n" \
    "%s\r\n"


int dslink_handshake_encode_pub_key(dslink_ecdh_context *key, char *buf,
                                    size_t bufLen, size_t *encLen) {
    int ret = 0;
    unsigned char pubKeyBin[65];
    size_t pubKeyBinLen = 0;

    if (dslink_crypto_ecp_point_write_binary(key->grp, key->Q,
                                                &pubKeyBinLen, pubKeyBin,
                                                sizeof(pubKeyBin)) < 0) {
        ret = DSLINK_CRYPT_KEY_ENCODE_ERR;
        goto exit;
    }

    if ((errno = dslink_base64_url_encode((unsigned char *) buf,
                                          bufLen, encLen, pubKeyBin,
                                          pubKeyBinLen)) != 0) {
        ret = DSLINK_CRYPT_BASE64_URL_ENCODE_ERR;
    }

exit:
    return ret;
}


int dslink_handshake_gen_auth_key(dslink_ecdh_context *key,
                                  const char *tempKey,
                                  const char *salt,
                                  unsigned char *buf,
                                  size_t bufLen) {
    int ret = 0;
    size_t olen = 0;
    if ((errno = dslink_base64_url_decode(buf, bufLen, &olen,
                                          (unsigned char *) tempKey,
                                          strlen(tempKey))) != 0) {
        ret = DSLINK_CRYPT_BASE64_URL_DECODE_ERR;
        goto exit;
    }

    EC_POINT* temp_key = EC_POINT_new(key->grp);
    if ((errno = dslink_crypto_ecp_point_read_binary(key->grp, temp_key,
                                               buf, olen)) != 0) {
        EC_POINT_free(temp_key);
        ret = DSLINK_HANDSHAKE_INVALID_TMP_KEY;
        goto exit;
    }

    if ((errno = dslink_crypto_ecdh_set_peer_public_key(key, temp_key)) != 0) {
        ret = DSLINK_HANDSHAKE_INVALID_TMP_KEY;
    }

    EC_POINT_free(temp_key);
    if(ret != 0) goto exit;

    if ((errno = dslink_crypto_ecdh_calc_secret(key, &olen, buf, bufLen)) != 0) {
        ret = DSLINK_HANDSHAKE_INVALID_TMP_KEY;
        goto exit;
    }

    {
        size_t saltLen = strlen(salt);
        size_t len = saltLen + olen;
        char *in = dslink_malloc(len + 1);
        if (!in) {
            ret = DSLINK_ALLOC_ERR;
            goto exit;
        }
        memcpy(in, salt, saltLen);
        memcpy(in + saltLen, (char *) buf, olen);
        *(in + len) = '\0';

        unsigned char auth[32];
        dslink_crypto_sha256((unsigned char *) in, len, auth);
        dslink_free(in);

        if ((errno = dslink_base64_url_encode(buf, bufLen, &olen, auth,
                                              sizeof(auth))) != 0) {
            ret = DSLINK_CRYPT_BASE64_URL_ENCODE_ERR;
        }
    }
exit:
    return ret;
}

/*
 *
 * Try to import key from file
 * if not available, generate it and save into a file
 *
 */
int dslink_handshake_key_pair_fs(dslink_ecdh_context *key,
                                 const char *fileName) {
    int ret = 0;
    FILE *f = fopen(fileName, "r");
    if (f) {
        char buf[1024];
        size_t len = fread(buf, 1, sizeof(buf) - 1, f);
        *(buf + len) = '\0';
        fclose(f);
        ret = dslink_handshake_read_key_pair(key, buf);
        if (ret != 0) {
            errno = ret;
            ret = DSLINK_CRYPT_KEY_DECODE_ERR;
        }
    } else {
        if ((ret = dslink_handshake_generate_key_pair(key)) != 0) {
            goto exit;
        }

        char buf[1024];
        int len;
        if ((len = dslink_handshake_store_key_pair(key, buf, sizeof(buf))) > 0) {
            f = fopen(fileName, "w");
            if (f) {
                fprintf(f, "%s", buf);
                fclose(f);
            } else {
                ret = DSLINK_OPEN_FILE_ERR;
            }
        } else {
            ret = len;
        }
    }
exit:
    return ret;
}

// write key into a file
int dslink_handshake_store_key_pair(dslink_ecdh_context *key,
                                    char *buf, size_t bufLen) {

    unsigned char* private_key_char = (unsigned char*) BN_bn2hex(key->d);
    size_t private_key_len = strlen((const char*)private_key_char);

    char* public_key_char = EC_POINT_point2hex(
            key->grp, key->Q, POINT_CONVERSION_UNCOMPRESSED, NULL);
    size_t public_key_len = strlen(public_key_char);

    size_t bufSize;
    {
        // Add additional size for the space separator and null terminator
        bufSize = private_key_len + public_key_len + 1;
        if (bufLen < bufSize) {
            return DSLINK_BUF_TOO_SMALL;
        }
        memcpy(buf, private_key_char, private_key_len);
        memset(buf + private_key_len, ' ', 1);
        memcpy(buf + private_key_len + 1, public_key_char, public_key_len);
        *(buf + bufSize) = '\0';
    }

    dslink_free(public_key_char);
    dslink_free(private_key_char);

    return (int) bufSize;
}

// ctx from buff
int dslink_handshake_read_key_pair(dslink_ecdh_context *ctx, char *buf) {
    char* private_key_char = NULL;
    char* public_key_char = NULL;
    BIGNUM* private_key = NULL;
    EC_POINT *public_key = NULL;

    int ret = 0;

    char *q = strchr(buf, ' ');
    if (!q) {
        ret = DSLINK_CRYPT_KEY_DECODE_ERR;
        goto exit;
    }

    size_t private_key_len = q - buf;
    if(!(private_key_char = dslink_malloc(private_key_len+1))) goto error;
    private_key_char[private_key_len] = '\0';
    size_t public_key_len = strlen(buf) - private_key_len - 1;
    if(!(public_key_char = dslink_malloc(public_key_len+1))) goto error;
    public_key_char[public_key_len] = '\0';

    memcpy(private_key_char, buf, private_key_len);
    memcpy(public_key_char, q+1, public_key_len);

    private_key = BN_new();
    int is_success = BN_hex2bn(&private_key, private_key_char);
    if(is_success == 0) goto error;

    public_key = EC_POINT_hex2point(ctx->grp, public_key_char, NULL, NULL);
    if(!public_key) goto error;

    if(dslink_crypto_ecdh_set_keys(ctx, private_key, public_key) != 0) goto error;

    exit:
    if(private_key_char) dslink_free(private_key_char);
    if(public_key_char) dslink_free(public_key_char);
    if(private_key) BN_free(private_key);
    if(public_key) EC_POINT_free(public_key);

    return ret;

    error:
    ret = DSLINK_CRYPT_KEY_DECODE_ERR;
    goto exit;
}

// generate ctx
int dslink_handshake_generate_key_pair(dslink_ecdh_context *ctx) {
    int ret = 0;

    if (dslink_crypto_ecdh_generate_keys(ctx) != 0) {
        ret = DSLINK_CRYPT_KEY_PAIR_GEN_ERR;
    }

    return ret;
}

char *dslink_handshake_generate_req(DSLink *link, char **dsId) {
    const size_t reqSize = 512;
    json_t *obj = json_object();
    char *req = dslink_malloc(reqSize);
    if (!(obj && req)) {
        json_decref(obj);
        DSLINK_CHECKED_EXEC(dslink_free, req);
        return NULL;
    }

    *dsId = NULL;
    char *body = NULL;

    unsigned char pubKeyBin[65];
    size_t pubKeyBinLen = 0;

    unsigned char pubKey[90];
    size_t pubKeyLen = 0;

    if(dslink_crypto_ecp_point_write_binary(link->key.grp, link->key.Q,
                                            &pubKeyBinLen, pubKeyBin,
                                            sizeof(pubKeyBin)) < 0) goto fail;

    if(dslink_base64_url_encode(pubKey, sizeof(pubKey),
                                &pubKeyLen, pubKeyBin,
                                pubKeyBinLen) != 0) goto fail;

    { // Generate dsId
        unsigned char sha[32];
        dslink_crypto_sha256(pubKeyBin, pubKeyBinLen, sha);

        unsigned char tmp[45];
        size_t tmpLen = 0;
        if ((errno = dslink_base64_url_encode((unsigned char *) tmp,
                                              sizeof(tmp),
                                              &tmpLen,
                                              sha,
                                              sizeof(sha))) != 0) {
            goto fail;
        }

        size_t nameLen = strlen(link->config.name);
        *dsId = dslink_malloc(nameLen + tmpLen + 2);
        if (!(*dsId)) {
            goto fail;
        }
        memcpy(*dsId, link->config.name, nameLen);
        *(*dsId + nameLen) = '-';
        memcpy((*dsId + nameLen + 1), (char *) tmp, tmpLen);
        *(*dsId + nameLen + tmpLen + 1) = '\0';
    }

    { // Create the request body
        json_object_set_new(obj, "publicKey", json_string_nocheck((char *) pubKey));
        json_object_set_new(obj, "isRequester", json_boolean(link->is_requester));
        json_object_set_new(obj, "isResponder", json_boolean(link->is_responder));
        json_object_set_new(obj, "version", json_string_nocheck("1.1.2"));
        json_object_set_new(obj, "formats", json_array());
        json_array_append(json_object_get(obj,"formats"), json_string_nocheck("json"));
        json_array_append(json_object_get(obj,"formats"), json_string_nocheck("msgpack"));

        if (link->link_data) {
            json_object_set(obj, "linkData", link->link_data);
        }
        body = json_dumps(obj, JSON_INDENT(2));
        if (!body) {
            goto fail;
        }
    }
    {
        char * encodedDsId = dslink_str_escape(*dsId);

        char uri[256];
        int reqLen = snprintf(uri, sizeof(uri) - 1, "%s?dsId=%s",
                              link->config.broker_url->uri, encodedDsId);
        dslink_free(encodedDsId);
        if (link->config.token) {
            char tokenId[17] = {0};
            memcpy(tokenId, link->config.token, 16);

            size_t id_len = strlen(*dsId) ;
            char *in = dslink_malloc(id_len + 49);
            memcpy(in, *dsId, id_len);
            memcpy(in + id_len, link->config.token, 48);
            *(in + id_len + 48) = '\0';

            unsigned char auth[32];
            dslink_crypto_sha256((unsigned char *) in, id_len + 48, auth);
            dslink_free(in);

            size_t outlen;
            char tokenHash[64] = {0};
            dslink_base64_url_encode((unsigned char*)tokenHash, sizeof(tokenHash), &outlen, auth, 32);

            reqLen += snprintf(uri+reqLen, sizeof(uri) - reqLen - 1, "&token=%s%s",
                               tokenId, tokenHash);
        }
        uri[reqLen] = '\0';
        reqLen = snprintf(req, reqSize - 1, DSLINK_POST_REQ, uri,
                          link->config.broker_url->host,
                          link->config.broker_url->port,
                          (int) strlen(body), body);
        req[reqLen] = '\0';
    }

exit:
    DSLINK_CHECKED_EXEC(dslink_free, body);
    json_decref(obj);
    return req;
fail:
    DSLINK_CHECKED_EXEC(dslink_free, *dsId);
    DSLINK_CHECKED_EXEC(dslink_free, req);
    req = NULL;
    *dsId = NULL;
    goto exit;
}

int dslink_parse_handshake_response(const char *resp, json_t **handshake) {
    int ret = 0;
    if (!resp) {
        ret = DSLINK_HANDSHAKE_NO_RESPONSE;
        goto exit;
    }

    char *index = strstr(resp, "401 Unauthorized");
    if (index) {
        ret = DSLINK_HANDSHAKE_UNAUTHORIZED;
        goto exit;
    }

    index = strchr(resp, '{');
    if (!index) {
        ret = DSLINK_HANDSHAKE_INVALID_RESPONSE;
        goto exit;
    }

    char *json = index;
    index = strrchr(json, '}');
    if (!index) {
        ret = DSLINK_HANDSHAKE_INVALID_RESPONSE;
        goto exit;
    }
    *(index + 1) = '\0';

    json_error_t jsonErr;
    *handshake = json_loads(json, 0, &jsonErr);
    if (!(*handshake)) {
        ret = DSLINK_ALLOC_ERR;
        goto exit;
    }

exit:
    return ret;
}

int dslink_handshake_generate(DSLink *link,
                              json_t **handshake,
                              char **dsId) {
    *handshake = NULL;
    Socket *sock = NULL;
    char *resp = NULL;
    int ret = 0;

    char *req = dslink_handshake_generate_req(link, dsId);
    if (!req) {
        ret = DSLINK_ALLOC_ERR;
        goto exit;
    }

    ret = dslink_socket_connect(&sock,
                                link->config.broker_url->host,
                                link->config.broker_url->port,
                                link->config.broker_url->secure);
    if (ret != 0) {
        goto exit;
    }

    if(dslink_socket_write(sock, req, strlen(req)) < 0)
    {
        ret = DSLINK_SOCK_WRITE_ERR;
        goto exit;
    }

    int respLen = 0;
    while (1) {
        char buf[1024];
        int read = dslink_socket_read(sock, buf, sizeof(buf) - 1);
        if (read <= 0) {
            break;
        }
        if (resp == NULL) {
            resp = dslink_malloc((size_t) read + 1);
            if (!resp) {
                ret = DSLINK_ALLOC_ERR;
                goto exit;
            }
            respLen = read;
            memcpy(resp, buf, (size_t) read);
            *(resp + respLen) = '\0';
        } else {
            char *tmp = realloc(resp, (size_t) respLen + read + 1);
            if (!tmp) {
                ret = DSLINK_ALLOC_ERR;
                goto exit;
            }
            resp = tmp;
            memcpy(resp + respLen, buf, (size_t) read);
            respLen += read;
            *(resp + respLen) = '\0';
        }
    }

    ret = dslink_parse_handshake_response(resp, handshake);
exit:
    DSLINK_CHECKED_EXEC(dslink_free, req);
    DSLINK_CHECKED_EXEC(dslink_free, resp);

    dslink_socket_close(&sock);

    return ret;
}
