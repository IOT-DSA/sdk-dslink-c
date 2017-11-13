#include <stddef.h>
#include <stdlib.h>

#include <errno.h>
#define LOG_TAG "socket"
#include <dslink/log.h>
#include <memory.h>


#include "dslink/mem/mem.h"
#include "dslink/socket_private.h"
#include "dslink/socket.h"
#include "dslink/err.h"

void dslink_print_ssl_error()
{
    log_err("Printing SSL error queue----->\n");

    do
    {
        unsigned long ssl_error = ERR_get_error();
        if(ssl_error == 0) break;
        log_err("SSL_ERROR : %s\n",ERR_error_string( ssl_error, NULL));

    }while(1);

    log_err("<--------Finished Printing SSL error queue\n");
}


Socket *dslink_socket_init(uint_fast8_t secure) {
    Socket *s = dslink_malloc(sizeof(Socket));
    if(!s) goto error;

    s->fd = socket(PF_INET, SOCK_STREAM, 0);
    if(s->fd == -1) goto deinit;

    bzero(&s->addr, sizeof(s->addr));
    s->addr.sin_family = AF_INET;
    s->secure = 0;

    if(secure)
    {
        INITIALIZE_OPENSSL();

        s->ssl = NULL;
        s->ssl_ctx = NULL;
        s->secure = 1;

        s->ssl_ctx = SSL_CTX_new(SSLv23_method());

        if ( !s->ssl_ctx )
        {
            log_err("Failed to create SSL Context because %s\n", ERR_reason_error_string(errno));
            dslink_print_ssl_error();
            goto deinit;
        }
    }

    return s;

    deinit:
    free(s);

    error:
    return NULL;
}

// TODO: in .h file function says "param: an initialized socket" but function initialized socket itself
int dslink_socket_connect(Socket **sock,
                          const char *address,
                          unsigned short port,
                          uint_fast8_t secure) {
    // TODO: correct it
    if(*sock == NULL)
    {
        *sock = dslink_socket_init(secure);
        if (!(*sock)) {
            return DSLINK_ALLOC_ERR;
        }
    }

    Socket *socket = *sock;

    socket->addr.sin_port = htons(port);

    struct hostent *host;
    if ( (host = gethostbyname(address)) == NULL )
        return DSLINK_SOCK_HOSTNAME_SET_ERR;

    socket->addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if ( connect(socket->fd, (struct sockaddr *)&socket->addr, sizeof(socket->addr)) != 0 )
    {
        return DSLINK_SOCK_CONNECT_ERR;
    }

    if(socket->secure)
    {
        INITIALIZE_OPENSSL();
        socket->ssl = SSL_new(socket->ssl_ctx);     // create new SSL connection state
        if(!socket->ssl) return DSLINK_SOCK_SSL_SETUP_ERR;

        if(SSL_set_fd(socket->ssl, socket->fd) != 1)
            return DSLINK_SOCK_SSL_CONFIG_ERR;

        int ret = SSL_connect(socket->ssl);
        if ( ret != 1 )
        {
            log_err("Failed to accept a secure connection %s\n", ERR_reason_error_string(ERR_get_error()));
            dslink_print_ssl_error();
            return DSLINK_SOCK_SSL_SETUP_ERR;
        }
    }

    return 0;
}

int dslink_socket_bind(Socket *socket, const char *address, unsigned short port) {
    socket->addr.sin_port = htons(port);

    struct hostent *host;
    if ( (host = gethostbyname(address)) == NULL )
        return DSLINK_SOCK_HOSTNAME_SET_ERR;

    socket->addr.sin_addr.s_addr = *(long*)(host->h_addr);

    int yes=1;

    if (setsockopt(socket->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1)
        return DSLINK_SOCK_BIND_ERR;

    if (  bind(socket->fd, (struct sockaddr *)&socket->addr, sizeof(socket->addr)) != 0 )
        return DSLINK_SOCK_BIND_ERR;

    if ( listen(socket->fd, 10) != 0 )
        return DSLINK_SOCK_BIND_ERR;

    return 0;
}


// Make it return new client socket or NULL
int dslink_socket_accept(Socket *server_socket, Socket **client_socket) {
    *client_socket = dslink_calloc(1, sizeof(Socket));
    if (!*client_socket) {
        goto fail;
    }

    Socket *client = *client_socket;

    int len = sizeof(struct sockaddr_in);
    client->fd = accept(server_socket->fd, (__SOCKADDR_ARG) &client->addr, (socklen_t*)&len);

    if(client->fd == -1)
    {
        log_err("Failed to accept a client connection, errno %d\n", errno);
        dslink_socket_free(&client);
        return -1;
    }

    client->secure = server_socket->secure;
    if(client->secure)
    {
        client->ssl = NULL;
        client->ssl_ctx = NULL;

        client->ssl = SSL_new(server_socket->ssl_ctx);
        int ret = SSL_set_fd(client->ssl, client->fd);
        (void) ret;

        if ( (ret = SSL_accept(client->ssl)) == -1 )
        {
            log_err("Failed to accept a client connection as SSL, errno %d\n", SSL_get_error(client->ssl, ret));
            dslink_print_ssl_error();
            dslink_socket_close(&client);
            return -1;
        }
    }

    log_debug("Accepted a client connection\n");
    return 0;

    fail:
    {
        struct sockaddr_in addr;
        int len = sizeof(struct sockaddr_in);
        int client_fd = accept(server_socket->fd, (__SOCKADDR_ARG) &addr, (socklen_t*)&len);
        close(client_fd);
    }

    return -1;
}


int dslink_socket_read(Socket *sock, char *buf, size_t len) {
    if(!sock) return DSLINK_SOCK_READ_ERR;

    int r;

    if (sock->secure)
    {
        r = SSL_read(sock->ssl, (unsigned char *) buf, len);
    }
    else
    {
        r = recv(sock->fd, (unsigned char *) buf, len, MSG_WAITALL);
    }

    if (r < 0) {
        if(errno == EAGAIN)
            return DSLINK_SOCK_WOULD_BLOCK;

        log_err("read error with errno %d\n", errno);

        if(sock->secure) dslink_print_ssl_error();

        return DSLINK_SOCK_READ_ERR;
    }

    return r;
}


int dslink_socket_write(Socket *sock, char *buf, size_t len) {
    if(!sock) return DSLINK_SOCK_WRITE_ERR;

    int r;

    if (sock->secure)
        r = SSL_write(sock->ssl, (unsigned char *) buf, len);
    else
        r = send(sock->fd , (unsigned char *) buf , len , 0);

    if (r < 0)
    {
        if(errno == EAGAIN) return DSLINK_SOCK_WOULD_BLOCK;

        log_err("write error with errno %d\n", errno);
        if(sock->secure) dslink_print_ssl_error();

        return DSLINK_SOCK_WRITE_ERR;
    }

    return r;
}

void dslink_socket_close_nofree(Socket **sock_ptr) {
    if(!sock_ptr) return;

    Socket *sock = *sock_ptr;
    if(!sock) return;

    if (sock->secure) {
        if(sock->ssl)
        {
            int ret = SSL_shutdown(sock->ssl);
            if(ret != 0) log_err("SSL cannot be closed!\n");
        }
    }

    if(sock->fd >= 0) {
        int ret = close(sock->fd);
        if(ret != 0) log_err("Socket cannot be closed!\n");
        sock->fd = -1;
    }
}

void dslink_socket_free(Socket **sock_ptr) {
    if(!sock_ptr) return;

    Socket *sock = *sock_ptr;
    if(!sock) return;

    if (sock->secure) {
        if(sock->ssl)
            SSL_free(sock->ssl);
        sock->ssl = NULL;

        if (sock->ssl_ctx)
            SSL_CTX_free(sock->ssl_ctx);
        sock->ssl_ctx = NULL;
    }

    dslink_free(sock);
    *sock_ptr = NULL;
}


void dslink_socket_close(Socket **sock_ptr) {
    dslink_socket_close_nofree(sock_ptr);
    dslink_socket_free(sock_ptr);
}

static int __OPEN_SSL_INITIALIZED = 0;

void INITIALIZE_OPENSSL(){
    if(!__OPEN_SSL_INITIALIZED)
    {
        SSL_library_init();            // SSL BUG

        OpenSSL_add_all_algorithms();
        SSL_load_error_strings();

        __OPEN_SSL_INITIALIZED = 1;
    }
}

#include <fcntl.h>
#include <arpa/inet.h>

int dslink_socket_set_nonblock(Socket *socket)
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
    u_long n = 1;
    return( ioctlsocket( socket->fd, FIONBIO, &n ) );
#else
    return( fcntl( socket->fd, F_SETFL, fcntl( socket->fd, F_GETFL ) | O_NONBLOCK ) );
#endif
}

int dslink_socket_set_block(Socket *socket)
{
#if ( defined(_WIN32) || defined(_WIN32_WCE) ) && !defined(EFIX64) && \
    !defined(EFI32)
    u_long n = 0;
    return( ioctlsocket( socket->fd, FIONBIO, &n ) );
#else
    return( fcntl( socket->fd, F_SETFL, fcntl( socket->fd, F_GETFL ) & ~O_NONBLOCK ) );
#endif
}

int dslink_check_connection(Socket *socket)
{
    int error_code;
    socklen_t error_code_size = sizeof(error_code);
    getsockopt(socket->fd, SOL_SOCKET, SO_ERROR, &error_code, &error_code_size);

    if (error_code != 0) {
        /* there was a problem getting the error code */
        log_warn("socket error code: %s\n", strerror(error_code));
        return -1;
    }
    return 0;
}



#define SOCK_ADDR_IN6_PTR(sa)	((struct sockaddr_in6 *)(sa))
#define SOCK_ADDR_IN6_ADDR(sa)	SOCK_ADDR_IN6_PTR(sa)->sin6_addr
#define SOCK_ADDR_IN_PTR(sa)	((struct sockaddr_in *)(sa))
#define SOCK_ADDR_IN_ADDR(sa)	SOCK_ADDR_IN_PTR(sa)->sin_addr

// function adapted from :
// https://opensource.apple.com/source/postfix/postfix-197/postfix/src/util/sock_addr.c
int dslink_check_socket_local(Socket *socket)
{
    unsigned long inaddr;
    struct sockaddr * sa = (struct sockaddr*) &socket->addr;

    if (sa->sa_family == AF_INET)
    {
        inaddr = ntohl(SOCK_ADDR_IN_ADDR(sa).s_addr);
        return (IN_CLASSA(inaddr)
                && ((inaddr & IN_CLASSA_NET) >> IN_CLASSA_NSHIFT)
                   == IN_LOOPBACKNET);
    }
    else if (sa->sa_family == AF_INET6)
    {
	    return (IN6_IS_ADDR_LOOPBACK(&SOCK_ADDR_IN6_ADDR(sa)));
    }
    else
    {
        log_fatal("sock_addr_in_loopback: unsupported address family %d", sa->sa_family);
    }

    return DSLINK_UNSUPPORTED_ADDRESS_FAMILY;
}
