#include <mbedtls/sha256.h>
#include <errno.h>
#include <string.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>

#include "dslink/base64_url.h"
#include "dslink/handshake.h"
#include "dslink/err.h"
#include "dslink/utils.h"

#define DSLINK_POST_REQ \
    "POST %s HTTP/1.1\r\n" \
    "Host: %s:%d\r\n" \
    "Content-Length: %d\r\n\r\n" \
    "%s\r\n"

int dslink_handshake_get_group(mbedtls_ecp_group *grp) {
    mbedtls_ecp_group_init(grp);
    const mbedtls_ecp_curve_info *info
        = mbedtls_ecp_curve_info_from_grp_id(MBEDTLS_ECP_DP_SECP256R1);
    if (!info) {
        return DSLINK_CRYPT_MISSING_CURVE;
    }

    if ((errno = mbedtls_ecp_group_load(grp, info->grp_id)) != 0) {
        return DSLINK_CRYPT_GROUP_LOAD_ERR;
    }

    return 0;
}

int dslink_handshake_encode_pub_key(mbedtls_ecdh_context *key, char *buf,
                                    size_t bufLen, size_t *encLen) {
    int ret = 0;
    unsigned char pubKeyBin[65];
    size_t pubKeyBinLen = 0;

    if ((errno = mbedtls_ecp_point_write_binary(&key->grp,
                                                &key->Q,
                                                MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                &pubKeyBinLen, pubKeyBin,
                                                sizeof(pubKeyBin))) != 0) {
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

int dslink_handshake_gen_auth_key(mbedtls_ecdh_context *key,
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

    if ((errno = mbedtls_ecp_point_read_binary(&key->grp, &key->Qp,
                                               buf, olen)) != 0) {
        ret = DSLINK_HANDSHAKE_INVALID_TMP_KEY;
        goto exit;
    }

    if ((errno = mbedtls_ecdh_calc_secret(key, &olen, buf,
                                          bufLen, NULL, NULL)) != 0) {
        ret = DSLINK_HANDSHAKE_INVALID_TMP_KEY;
        goto exit;
    }

    {
        size_t saltLen = strlen(salt);
        size_t len = saltLen + olen;
        char *in = malloc(len + 1);
        if (!in) {
            ret = DSLINK_ALLOC_ERR;
            goto exit;
        }
        memcpy(in, salt, saltLen);
        memcpy(in + saltLen, (char *) buf, olen);
        *(in + len) = '\0';

        unsigned char auth[32];
        mbedtls_sha256((unsigned char *) in, len, auth, 0);
        free(in);

        if ((errno = dslink_base64_url_encode(buf, bufLen, &olen, auth,
                                              sizeof(auth))) != 0) {
            ret = DSLINK_CRYPT_BASE64_URL_ENCODE_ERR;
        }
    }
exit:
    return ret;
}

int dslink_handshake_key_pair_fs(mbedtls_ecdh_context *key,
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
        if ((len = dslink_handshake_store_key_pair(key, buf,
                                                   sizeof(buf))) > 0) {
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

int dslink_handshake_store_key_pair(mbedtls_ecdh_context *key,
                                    char *buf, size_t bufLen) {
    unsigned char dEnc[45];
    char qEnc[90];
    size_t dEncLen = 0;
    size_t qEncLen = 0;
    {
        unsigned char dBin[33];
        if ((errno = mbedtls_mpi_write_binary(&key->d,
                                              dBin, sizeof(dBin))) != 0) {
            return DSLINK_CRYPT_KEY_ENCODE_ERR;
        }

        if (dslink_base64_url_encode(dEnc, sizeof(dEnc), &dEncLen,
                                     dBin, sizeof(dBin)) != 0) {
            return DSLINK_CRYPT_BASE64_URL_ENCODE_ERR;
        }
    }

    {
        int ret;
        if ((ret = dslink_handshake_encode_pub_key(key, qEnc, sizeof(qEnc),
                                                   &qEncLen)) != 0) {
            return ret;
        }
    }

    size_t bufSize;
    {
        // Add additional size for the space separator and null terminator
        bufSize = dEncLen + qEncLen + 1;
        if (bufLen < bufSize) {
            return DSLINK_BUF_TOO_SMALL;
        }
        memcpy(buf, dEnc, dEncLen);
        memset(buf + dEncLen, ' ', 1);
        memcpy(buf + dEncLen + 1, qEnc, qEncLen);
        *(buf + bufSize) = '\0';
    }

    return (int) bufSize;
}

int dslink_handshake_read_key_pair(mbedtls_ecdh_context *ctx, char *buf) {
    mbedtls_ecdh_init(ctx);
    dslink_handshake_get_group(&ctx->grp);
    char *q = strchr(buf, ' ');
    if (!q || *(q + 1) == '\0') {
        errno = 0;
        return DSLINK_CRYPT_KEY_DECODE_ERR;
    }

    size_t len = (q - buf);
    unsigned char dec[90];
    size_t decLen = 0;
    if (dslink_base64_url_decode(dec, sizeof(dec), &decLen,
                                 (unsigned char *) buf, len) != 0) {
        return DSLINK_CRYPT_BASE64_URL_DECODE_ERR;
    }

    if ((errno = mbedtls_mpi_read_binary(&ctx->d, dec, decLen)) != 0) {
        return DSLINK_CRYPT_KEY_DECODE_ERR;
    }

    len = strlen(buf) - len - 1;
    if (dslink_base64_url_decode(dec, sizeof(dec), &decLen,
                                 (unsigned char *) (q + 1), len) != 0) {
        return DSLINK_CRYPT_BASE64_URL_DECODE_ERR;
    }

    if ((errno = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Q,
                                               dec, decLen)) != 0) {
        return DSLINK_CRYPT_KEY_DECODE_ERR;
    }

    return 0;
}

int dslink_handshake_generate_key_pair(mbedtls_ecdh_context *ctx) {

    mbedtls_entropy_context ent;
    mbedtls_entropy_init(&ent);
    mbedtls_ecdh_init(ctx);

    int ret = 0;
    if ((ret = dslink_handshake_get_group(&ctx->grp)) != 0) {
        goto exit;
    }

    if ((errno = mbedtls_ecp_gen_keypair(&ctx->grp,
                                         &ctx->d,
                                         &ctx->Q,
                                         mbedtls_entropy_func, &ent)) != 0) {
        ret = DSLINK_CRYPT_KEY_PAIR_GEN_ERR;
        goto exit;
    }

exit:
    mbedtls_entropy_free(&ent);
    return ret;
}

int dslink_handshake_generate(Url *url,
                              mbedtls_ecdh_context *key,
                              const char *name,
                              uint8_t isRequester,
                              uint8_t isResponder,
                              json_t **handshake,
                              char **dsId) {
    *handshake = NULL;
    Socket *sock = NULL;
    char *resp = NULL;
    char *body = NULL;
    int ret = 0;

    unsigned char pubKeyBin[65];
    size_t pubKeyBinLen = 0;

    unsigned char pubKey[90];
    size_t pubKeyLen = 0;

    if ((errno = mbedtls_ecp_point_write_binary(&key->grp,
                                                &key->Q,
                                                MBEDTLS_ECP_PF_UNCOMPRESSED,
                                                &pubKeyBinLen, pubKeyBin,
                                                sizeof(pubKeyBin))) != 0) {
        ret = DSLINK_CRYPT_KEY_ENCODE_ERR;
        goto exit;
    }

    if ((errno = dslink_base64_url_encode(pubKey,
                                          sizeof(pubKey),
                                          &pubKeyLen,
                                          pubKeyBin,
                                          pubKeyBinLen)) != 0) {
        ret = DSLINK_CRYPT_BASE64_URL_ENCODE_ERR;
        goto exit;
    }

    { // Generate dsId
        unsigned char sha[32];
        mbedtls_sha256(pubKeyBin, pubKeyBinLen, sha, 0);

        unsigned char tmp[45];
        size_t tmpLen = 0;
        if ((errno = dslink_base64_url_encode((unsigned char *) tmp,
                                              sizeof(tmp),
                                              &tmpLen,
                                              sha,
                                              sizeof(sha))) != 0) {
            ret = DSLINK_CRYPT_BASE64_URL_ENCODE_ERR;
            goto exit;
        }

        size_t nameLen = strlen(name);
        *dsId = malloc(nameLen + tmpLen + 2);
        if (!(*dsId)) {
            ret = DSLINK_ALLOC_ERR;
            goto exit;
        }
        memcpy(*dsId, name, nameLen);
        *(*dsId + nameLen) = '-';
        memcpy((*dsId + nameLen + 1), (char *) tmp, tmpLen);
        *(*dsId + nameLen + tmpLen + 1) = '\0';
    }

    { // Create the request body
        json_t *obj = json_object();
        if (!obj) {
            ret = DSLINK_ALLOC_ERR;
            goto exit;
        }

        json_object_set_new(obj, "publicKey", json_string((char *) pubKey));
        json_object_set_new(obj, "isRequester", json_boolean(isRequester));
        json_object_set_new(obj, "isResponder", json_boolean(isResponder));
        json_object_set_new(obj, "version", json_string("1.1.2"));
        body = json_dumps(obj, JSON_INDENT(2));
        json_delete(obj);
        if (!body) {
            ret = DSLINK_ALLOC_ERR;
            goto exit;
        }
    }

    char req[512];
    size_t reqLen;
    {
        char uri[128];
        snprintf(uri, sizeof(uri), "%s?dsId=%s", url->uri, *dsId);
        reqLen = snprintf(req, sizeof(req), DSLINK_POST_REQ, uri, url->host,
                          url->port, (int) strlen(body), body);
    }

    if ((ret = dslink_socket_connect(&sock, url->host,
                                     url->port, url->secure)) != 0) {
        goto exit;
    }

    dslink_socket_write(sock, req, reqLen);

    int respLen = 0;
    while (1) {
        char buf[1024];
        int read = dslink_socket_read(sock, buf, sizeof(buf) - 1);
        if (read <= 0) {
            break;
        }
        if (resp == NULL) {
            resp = malloc((size_t) read + 1);
            if (!resp) {
                ret = DSLINK_ALLOC_ERR;
                goto exit;
            }
            respLen = read;
            memcpy(resp, buf, read);
            *(resp + respLen) = '\0';
        } else {
            char *tmp = realloc(resp, (size_t) respLen + read + 1);
            if (!tmp) {
                free(resp);
                ret = DSLINK_ALLOC_ERR;
                goto exit;
            }
            resp = tmp;
            memcpy(resp + respLen, buf, read);
            respLen += read;
            *(resp + respLen) = '\0';
        }
    }

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
    const char *id = json_string_value(json_object_get(*handshake, "id"));
    if (id) {
        free(*dsId);
        size_t size = strlen(id) + 1;
        *dsId = malloc(size);
        if (!(*dsId)) {
            ret = DSLINK_ALLOC_ERR;
            json_delete(*handshake);
            *handshake = NULL;
            goto exit;
        }
        memcpy(*dsId, id, size);
    }

exit:
    DSLINK_CHECKED_EXEC(free, body);
    DSLINK_CHECKED_EXEC(free, resp);
    DSLINK_CHECKED_EXEC(dslink_socket_close, sock);
    return ret;
}
