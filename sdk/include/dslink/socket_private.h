#ifndef SDK_DSLINK_C_SOCKET_PRIVATE_H
#define SDK_DSLINK_C_SOCKET_PRIVATE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>

#include <unistd.h> // For socket close function

struct Socket {
    int fd;
    struct sockaddr_in addr;

    uint_fast8_t secure;
    SSL_CTX *ssl_ctx;
    SSL *ssl;

};




#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_SOCKET_PRIVATE_H
