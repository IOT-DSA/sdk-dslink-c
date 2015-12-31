#ifndef SDK_DSLINK_C_ERR_H
#define SDK_DSLINK_C_ERR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <errno.h>

#define DSLINK_ALLOC_ERR                     -0x1000
#define DSLINK_BUF_TOO_SMALL                 -0x1001
#define DSLINK_OPEN_FILE_ERR                 -0x1002

#define DSLINK_SOCK_CONNECT_ERR              -0x2000
#define DSLINK_SOCK_SSL_CONFIG_ERR           -0x2001
#define DSLINK_SOCK_SSL_SETUP_ERR            -0x2002
#define DSLINK_SOCK_SSL_HOSTNAME_SET_ERR     -0x2003
#define DSLINK_SOCK_SSL_HANDSHAKE_ERR        -0x2004
#define DSLINK_SOCK_READ_ERR                 -0x2005
#define DSLINK_SOCK_WRITE_ERR                -0x2006

#define DSLINK_CRYPT_ENTROPY_SEED_ERR        -0x3000
#define DSLINK_CRYPT_MISSING_CURVE           -0x3001
#define DSLINK_CRYPT_GROUP_LOAD_ERR          -0x3002
#define DSLINK_CRYPT_KEY_PAIR_GEN_ERR        -0x3003
#define DSLINK_CRYPT_KEY_ENCODE_ERR          -0x3004
#define DSLINK_CRYPT_KEY_DECODE_ERR          -0x3005
#define DSLINK_CRYPT_BASE64_URL_ENCODE_ERR   -0x3006
#define DSLINK_CRYPT_BASE64_URL_DECODE_ERR   -0x3007

#define DSLINK_HANDSHAKE_UNAUTHORIZED        -0x4000
#define DSLINK_HANDSHAKE_NO_RESPONSE         -0x4001
#define DSLINK_HANDSHAKE_INVALID_RESPONSE    -0x4002
#define DSLINK_HANDSHAKE_INVALID_TMP_KEY     -0x4003

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_ERR_H
