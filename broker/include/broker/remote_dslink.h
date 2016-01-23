#ifndef BROKER_REMOTE_DSLINK_H
#define BROKER_REMOTE_DSLINK_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RemoteAuth {

    char salt[48];
    mbedtls_ecdh_context tempKey;
    const char *pubKey;

} RemoteAuth;

typedef struct RemoteDSLink {

    RemoteAuth *auth;

} RemoteDSLink;

#ifdef __cplusplus
}
#endif

#endif // BROKER_REMOTE_DSLINK_H
