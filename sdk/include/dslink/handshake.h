#ifndef SDK_DSLINK_C_HANDSHAKE_H
#define SDK_DSLINK_C_HANDSHAKE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mbedtls/ecdh.h>
#include <jansson.h>

#include "dslink/url.h"
#include "dslink/socket.h"
#include "dslink/dslink.h"

int dslink_handshake_get_group(mbedtls_ecp_group *grp);
int dslink_handshake_encode_pub_key(mbedtls_ecdh_context *key,
                                    char *buf, size_t bufLen, size_t *encLen);
int dslink_handshake_gen_auth_key(mbedtls_ecdh_context *key,
                                  const char *tempKey,
                                  const char *salt,
                                  unsigned char *buf,
                                  size_t bufLen);

int dslink_handshake_key_pair_fs(mbedtls_ecdh_context *ctx,
                                 const char *fileName);
int dslink_handshake_store_key_pair(mbedtls_ecdh_context *key,
                                    char *buf, size_t bufLen);
int dslink_handshake_read_key_pair(mbedtls_ecdh_context *ctx,
                                   char *buf);
int dslink_handshake_generate_key_pair(mbedtls_ecdh_context *ctx);

char *dslink_handshake_generate_req(DSLink *link, char **dsId);
int dslink_parse_handshake_response(const char *resp,
                                    json_t **handshake);
int dslink_handshake_generate(DSLink *link,
                              json_t **handshake,
                              char **dsId);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_HANDSHAKE_H
