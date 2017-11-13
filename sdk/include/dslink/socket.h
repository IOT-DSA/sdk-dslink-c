#ifndef SDK_DSLINK_C_SOCKET_H
#define SDK_DSLINK_C_SOCKET_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

typedef struct Socket Socket;

void dslink_print_ssl_error();


/**
 * \brief          Allocates the memory needed for a Socket. This is useful
 *                 to provide Socket API access for the server. Connecting
 *                 to outbound servers must not use this as it is automatically
 *                 handled.
 *
 * \param secure   Whether to allocate a SecureSocket which is necessary for
 *                 SSL connections.
 */
Socket *dslink_socket_init(uint_fast8_t secure);

/**
 * \brief          Connects to a designated server. All parameters must be
 *                 initialized otherwise the behavior is undefined.
 *
 * \param sock     An initialized socket. It must not be connected to any
 *                 server. Using an already connected socket will result
 *                 in undefined behavior.
 * \param address  Address of the server.
 * \param port     Port of the server.
 * \param secure   Whether the connection to the server is over SSL or not.
 *
 * \return         0 on success, otherwise an error has occurred.
 */
int dslink_socket_connect(Socket **sock,
                          const char *address,
                          unsigned short port,
                          uint_fast8_t secure);

int dslink_socket_bind(Socket *socket, const char *address, unsigned short port);
int dslink_socket_accept(Socket *server_socket, Socket **client_socket);

int dslink_socket_read(Socket *sock, char *buf, size_t len);
int dslink_socket_write(Socket *sock, char *buf, size_t len);

void dslink_socket_close(Socket **sock_ptr);
void dslink_socket_close_nofree(Socket **sock_ptr);
void dslink_socket_free(Socket **sock_ptr);

int dslink_socket_set_nonblock(Socket *socket);
int dslink_socket_set_block(Socket *socket);

int dslink_check_connection(Socket *socket);
int dslink_check_socket_local(Socket *socket);

void INITIALIZE_OPENSSL();




#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_SOCKET_H
