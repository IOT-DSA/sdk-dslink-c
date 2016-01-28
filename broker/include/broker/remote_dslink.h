#ifndef BROKER_REMOTE_DSLINK_H
#define BROKER_REMOTE_DSLINK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <mbedtls/ecdh.h>

#include <dslink/col/map.h>
#include <dslink/socket.h>

typedef struct RemoteAuth {

    char salt[48];
    mbedtls_ecdh_context tempKey;
    const char *pubKey;

} RemoteAuth;

typedef struct RemoteDSLink {

    uint8_t isRequester;
    uint8_t isResponder;

    struct DownstreamNode *node;
    Socket *socket;
    RemoteAuth *auth;

    const char *dsId;
    const char *name;

    // Map<uint32_t *, Stream *>
    Map local_streams;

    // Map<char *, Stream *>
    Map list_streams;

} RemoteDSLink;

int broker_remote_dslink_init(RemoteDSLink *link);
void broker_remote_dslink_free(RemoteDSLink *link);

#ifdef __cplusplus
}
#endif

#endif // BROKER_REMOTE_DSLINK_H
