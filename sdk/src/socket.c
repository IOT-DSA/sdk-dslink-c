#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

#include "dslink/mem/mem.h"
#include "dslink/socket_private.h"
#include "dslink/socket.h"
#include "dslink/err.h"

Socket *dslink_socket_init(uint_fast8_t secure) {
    if (secure) {
        SslSocket *s = dslink_malloc(sizeof(SslSocket));
        if (!s) {
            return NULL;
        }
        s->secure = 1;
        mbedtls_net_init(&s->socket_ctx);
        mbedtls_entropy_init(&s->entropy);
        mbedtls_ctr_drbg_init(&s->drbg);
        mbedtls_ssl_init(&s->ssl);
        mbedtls_ssl_config_init(&s->conf);
        return (Socket *) s;
    } else {
        Socket *s = dslink_malloc(sizeof(Socket));
        if (!s) {
            return NULL;
        }
        s->secure = 0;
        mbedtls_net_init(&s->socket_ctx);
        return s;
    }
}

static
int dslink_socket_connect_secure(SslSocket *sock,
                                 const char *address,
                                 unsigned short port) {
    if ((errno = mbedtls_ctr_drbg_seed(&sock->drbg, mbedtls_entropy_func,
                                       &sock->entropy, NULL, 0)) != 0) {
        return DSLINK_CRYPT_ENTROPY_SEED_ERR;
    }

    char num[6];
    snprintf(num, sizeof(num), "%d", port);
    if ((errno = mbedtls_net_connect(&sock->socket_ctx, address,
                                     num, MBEDTLS_NET_PROTO_TCP)) != 0) {
        return DSLINK_SOCK_CONNECT_ERR;
    }

    if ((errno = mbedtls_ssl_config_defaults(&sock->conf,
                                             MBEDTLS_SSL_IS_CLIENT,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        return DSLINK_SOCK_SSL_CONFIG_ERR;
    }
    mbedtls_ssl_conf_authmode(&sock->conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&sock->conf, mbedtls_ctr_drbg_random, &sock->drbg);

    if ((errno = mbedtls_ssl_setup(&sock->ssl, &sock->conf)) != 0) {
        return DSLINK_SOCK_SSL_SETUP_ERR;
    }

    if ((errno = mbedtls_ssl_set_hostname(&sock->ssl, "_")) != 0) {
        return DSLINK_SOCK_SSL_HOSTNAME_SET_ERR;
    }

    mbedtls_ssl_set_bio(&sock->ssl, &sock->socket_ctx,
                        mbedtls_net_send, mbedtls_net_recv, NULL);

    int stat;
    while ((stat = mbedtls_ssl_handshake(&sock->ssl)) != 0) {
        if (stat != MBEDTLS_ERR_SSL_WANT_READ
            && stat != MBEDTLS_ERR_SSL_WANT_WRITE) {
            errno = stat;
            return DSLINK_SOCK_SSL_HANDSHAKE_ERR;
        }
    }

    return 0;
}

static
int dslink_socket_connect_insecure(Socket *sock,
                                   const char *address,
                                   unsigned short port) {
    mbedtls_net_init(&sock->socket_ctx);
    char num[6];
    snprintf(num, sizeof(num), "%d", port);
    if ((errno = mbedtls_net_connect(&sock->socket_ctx, address,
                                     num, MBEDTLS_NET_PROTO_TCP)) != 0) {
        return DSLINK_SOCK_CONNECT_ERR;
    }
    return 0;
}

int dslink_socket_connect(Socket **sock,
                          const char *address,
                          unsigned short port,
                          uint_fast8_t secure) {
    *sock = dslink_socket_init(secure);
    mbedtls_net_set_nonblock(&(*sock)->socket_ctx);
    if (!(*sock)) {
        return DSLINK_ALLOC_ERR;
    }
    if (secure) {
        SslSocket *s = (SslSocket *) *sock;
        return dslink_socket_connect_secure(s, address, port);
    } else {
        return dslink_socket_connect_insecure(*sock, address, port);
    }
}

int dslink_socket_read(Socket *sock, char *buf, size_t len) {
    int r;
    if (sock->secure) {
        r = mbedtls_ssl_read(&((SslSocket *) sock)->ssl,
                             (unsigned char *) buf, len);
    } else {
        r = mbedtls_net_recv(&sock->socket_ctx, (unsigned char *) buf, len);
    }
    if (r < 0) {
        errno = r;
        return DSLINK_SOCK_READ_ERR;
    }
    return r;
}

int dslink_socket_write(Socket *sock, char *buf, size_t len) {
    int r;
    if (sock->secure) {
        r = mbedtls_ssl_write(&((SslSocket *) sock)->ssl,
                              (unsigned char *) buf, len);
    } else {
        r = mbedtls_net_send(&sock->socket_ctx, (unsigned char *) buf, len);
    }
    if (r < 0) {
        return DSLINK_SOCK_WRITE_ERR;
    }
    return r;
}

void dslink_socket_close_nofree(Socket *sock) {
    if (sock->secure) {
        SslSocket *s = (SslSocket *) sock;
        mbedtls_ssl_close_notify(&s->ssl);
        mbedtls_entropy_free(&s->entropy);
        mbedtls_ctr_drbg_free(&s->drbg);
        mbedtls_ssl_free(&s->ssl);
        mbedtls_ssl_config_free(&s->conf);
    }
    mbedtls_net_free(&sock->socket_ctx);
}

void dslink_socket_close(Socket *sock) {
    dslink_socket_close_nofree(sock);
    dslink_socket_free(sock);
}

void dslink_socket_free(Socket *sock) {
    dslink_free(sock);
}
