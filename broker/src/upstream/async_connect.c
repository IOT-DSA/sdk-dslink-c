
#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include "mbedtls/net.h"

#include <string.h>

#if (defined(_WIN32) || defined(_WIN32_WCE)) && !defined(EFIX64) && \
    !defined(EFI32)

#ifdef _WIN32_WINNT
#undef _WIN32_WINNT
#endif
/* Enables getaddrinfo() & Co */
#define _WIN32_WINNT 0x0501
#include <ws2tcpip.h>

#include <winsock2.h>
#include <windows.h>

#if defined(_MSC_VER)
#if defined(_WIN32_WCE)
#pragma comment( lib, "ws2.lib" )
#else
#pragma comment( lib, "ws2_32.lib" )
#endif
#endif /* _MSC_VER */

#define read(fd,buf,len)        recv(fd,(char*)buf,(int) len,0)
#define write(fd,buf,len)       send(fd,(char*)buf,(int) len,0)
#define close(fd)               closesocket(fd)

static int wsa_init_done = 0;

#else /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <netdb.h>
#include <errno.h>

#endif /* ( _WIN32 || _WIN32_WCE ) && !EFIX64 && !EFI32 */

/* Some MS functions want int and MSVC warns if we pass size_t,
 * but the standard fucntions use socklen_t, so cast only for MSVC */
#if defined(_MSC_VER)
#define MSVC_INT_CAST   (int)
#else
#define MSVC_INT_CAST
#endif

#include <stdlib.h>
#include <stdio.h>

#include <time.h>

#include <stdint.h>


#include <string.h>

#include <stddef.h>
#include <stdlib.h>
#include <errno.h>

#include "dslink/mem/mem.h"
#include "dslink/socket_private.h"
#include "dslink/socket.h"
#include "dslink/err.h"
#include "../../include/broker/upstream/upstream_handshake.h"

static int net_prepare( void )
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
    WSADATA wsaData;

    if( wsa_init_done == 0 )
    {
        if( WSAStartup( MAKEWORD(2,0), &wsaData ) != 0 )
            return( MBEDTLS_ERR_NET_SOCKET_FAILED );

        wsa_init_done = 1;
    }
#else
#if !defined(EFIX64) && !defined(EFI32)
    signal( SIGPIPE, SIG_IGN );
#endif
#endif
    return( 0 );
}

int connectConnCheck(UpstreamPoll *upstreamPoll) {
    return connect( upstreamPoll->sock->socket_ctx.fd, upstreamPoll->conCheckAddrList->ai_addr, MSVC_INT_CAST upstreamPoll->conCheckAddrList->ai_addrlen );
}

static
int mbedtls_net_connect_async(UpstreamPoll *upstreamPoll, const char *host, const char *port, int proto )
{
    mbedtls_net_context *ctx = &upstreamPoll->sock->socket_ctx;

    int ret;
    struct addrinfo hints, *addr_list;

    if( ( ret = net_prepare() ) != 0 )
        return( ret );

    /* Do name resolution with both IPv6 and IPv4 */
    memset( &hints, 0, sizeof( hints ) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = proto == MBEDTLS_NET_PROTO_UDP ? SOCK_DGRAM : SOCK_STREAM;
    hints.ai_protocol = proto == MBEDTLS_NET_PROTO_UDP ? IPPROTO_UDP : IPPROTO_TCP;

    if( getaddrinfo( host, port, &hints, &addr_list ) != 0 )
        return( MBEDTLS_ERR_NET_UNKNOWN_HOST );

    /* Try the sockaddrs until a connection succeeds */
    ret = MBEDTLS_ERR_NET_UNKNOWN_HOST;
    ctx->fd = (int) socket( addr_list->ai_family, addr_list->ai_socktype,
                            addr_list->ai_protocol );
    if( ctx->fd < 0 )
    {
        freeaddrinfo( addr_list );
        return MBEDTLS_ERR_NET_SOCKET_FAILED;
    } else  {
        mbedtls_net_set_nonblock(ctx);
        if (connect( ctx->fd, addr_list->ai_addr, MSVC_INT_CAST addr_list->ai_addrlen ) != 0) {
            if (errno != 115 && errno != 114) {
                freeaddrinfo( addr_list );
                return MBEDTLS_ERR_NET_SOCKET_FAILED;
            }
        };
        upstreamPoll->conCheckAddrList = addr_list;
        return 0;
    }


}

static
int dslink_socket_connect_secure_async(UpstreamPoll *upstreamPoll,
                                 const char *address,
                                 unsigned short port) {
    SslSocket *sock = (SslSocket*)upstreamPoll->sock;
    if ((errno = mbedtls_ctr_drbg_seed(&sock->drbg, mbedtls_entropy_func,
                                       &sock->entropy, NULL, 0)) != 0) {
        return DSLINK_CRYPT_ENTROPY_SEED_ERR;
    }

    char num[6];
    snprintf(num, sizeof(num), "%d", port);
    if ((errno = mbedtls_net_connect_async(upstreamPoll, address,
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
int dslink_socket_connect_insecure_async(UpstreamPoll *upstreamPoll,
                                   const char *address,
                                   unsigned short port) {
    Socket *sock = upstreamPoll->sock;
    mbedtls_net_init(&sock->socket_ctx);
    char num[6];
    snprintf(num, sizeof(num), "%d", port);
    if ((errno = mbedtls_net_connect_async(upstreamPoll, address,
                                     num, MBEDTLS_NET_PROTO_TCP)) != 0) {
        return DSLINK_SOCK_CONNECT_ERR;
    }
    return 0;
}

int dslink_socket_connect_async(UpstreamPoll *upstreamPoll,
                          const char *address,
                          unsigned short port,
                          uint_fast8_t secure) {
    upstreamPoll->sock = dslink_socket_init(secure);
    mbedtls_net_set_nonblock(&upstreamPoll->sock->socket_ctx);
    if (!upstreamPoll->sock) {
        return DSLINK_ALLOC_ERR;
    }
    if (secure) {
        return dslink_socket_connect_secure_async(upstreamPoll, address, port);
    } else {
        return dslink_socket_connect_insecure_async(upstreamPoll, address, port);
    }
}
