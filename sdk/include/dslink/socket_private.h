#ifndef SDK_DSLINK_C_SOCKET_PRIVATE_H
#define SDK_DSLINK_C_SOCKET_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net.h>

struct SslSocket {

    uint_fast8_t secure;
    mbedtls_net_context socket_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;

};

struct Socket {

    uint_fast8_t secure;
    mbedtls_net_context socket_ctx;

};

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_SOCKET_PRIVATE_H
