#ifndef BROKER_REMOTE_DSLINK_H
#define BROKER_REMOTE_DSLINK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <mbedtls/ecdh.h>
#include <dslink/socket.h>

typedef struct RemoteAuth {

    char salt[48];
    mbedtls_ecdh_context tempKey;
    const char *pubKey;

} RemoteAuth;

typedef struct RemoteDSLink {

    RemoteAuth *auth;

    const char *dsId;
    uint8_t isRequester;
    uint8_t isResponder;

} RemoteDSLink;

#ifdef __cplusplus
}
#endif

#endif // BROKER_REMOTE_DSLINK_H
