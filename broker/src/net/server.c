#include <sys/select.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>

#define LOG_TAG "server"
#include <dslink/log.h>
#include <dslink/socket_private.h>

#include "broker/net/server.h"

typedef struct Client {
    Socket *sock;
    void *sock_data;
} Client;

int broker_start_server(json_t *config, void *data,
                        DataReadyCallback cb,
                        ClientErrorCallback cec) {
    json_incref(config);

    const char *host = NULL;
    const char *port = NULL;
    {
        json_t *http = json_object_get(config, "http");
        if (http) {
            json_t *enabled = json_object_get(http, "enabled");
            if (!(enabled && json_boolean_value(enabled))) {
                json_decref(config);
                return 0;
            }
            host = json_string_value(json_object_get(http, "host"));

            json_t *jsonPort = json_object_get(http, "port");
            if (jsonPort) {
                uint32_t p = (uint32_t) json_integer_value(jsonPort);

                char buf[8];
                int len = snprintf(buf, sizeof(buf) - 1, "%" PRIu32, p);
                buf[len] = '\0';
                port = buf;
            }
        }
    }

    if (!(host && port)) {
        json_decref(config);
        return 1;
    }

    mbedtls_net_context srv;
    mbedtls_net_init(&srv);
    if (mbedtls_net_bind(&srv, host, port, MBEDTLS_NET_PROTO_TCP) != 0) {
        log_fatal("Failed to bind to %s:%s\n", host, port);
        json_decref(config);
        return 1;
    } else {
        log_info("HTTP server bound to %s:%s\n", host, port);
    }

    Client **clients = calloc(1, sizeof(Client *));
    int clientsLen = 1;
    while (1) {
        fd_set readFds;
        FD_SET(srv.fd, &readFds);
        int maxFd = srv.fd;
        for (int i = 0; i < clientsLen; ++i) {
            Client *client = clients[i];
            if (client) {
                FD_SET(client->sock->socket_fd.fd, &readFds);
                if (client->sock->socket_fd.fd > maxFd) {
                    maxFd = client->sock->socket_fd.fd;
                }
            }
        }

        int ready = select(maxFd + 1, &readFds, NULL, NULL, NULL);
        if (ready < 0) {
            log_debug("Error in select(): %s\nclose all clients\n", strerror(errno));
            for (int i = 0; i < clientsLen; ++i) {
                Client *client = clients[i];
                if (client) {
                    cec(client->sock_data);
                    clients[i] = NULL;
                    dslink_socket_close(client->sock);
                    free(client);
                }
            }
            continue;
        }

        for (int i = 0; i < clientsLen; ++i) {
            Client *client = clients[i];
            if (client == NULL || !FD_ISSET(client->sock->socket_fd.fd, &readFds)) {
                continue;
            }

            cb(client->sock, data, &client->sock_data);
            if (client->sock->socket_fd.fd == -1) {
                // The callback closed the connection
                clients[i] = NULL;
                dslink_socket_free(client->sock);
                free(client);
            }
        }

        if (!FD_ISSET(srv.fd, &readFds)) {
            continue;
        }

        int i = 0;
        Client *client = NULL;
        for (; i < clientsLen; ++i) {
            // Look for an available opening in the clients array
            Client *tmp = clients[i];
            if (tmp == NULL) {
                client = clients[i] = calloc(1, sizeof(Client));
                if (client) {
                    client->sock = dslink_socket_init(0);
                    if (!client->sock) {
                        free(client);
                        client = clients[i] = NULL;
                    }
                }
                break;
            }
        }
        if (!client) {
            clientsLen++;
            Client **new = realloc(clients, sizeof(clients) * clientsLen);
            if (new) {
                clients = new;
                client = clients[i] = calloc(1, sizeof(Client));
                if (client) {
                    client->sock = dslink_socket_init(0);
                    if (!client->sock) {
                        free(client);
                        client = clients[i] = NULL;
                    }
                }
            } else {
                clientsLen--;
            }
        }

        if (client) {
            if (mbedtls_net_accept(&srv, &client->sock->socket_fd,
                                   NULL, 0, NULL) != 0) {
                log_warn("Failed to accept a client connection\n");
                dslink_socket_free(client->sock);
                free(client);
                clients[i] = NULL;
                continue;
            }

            mbedtls_net_set_nonblock(&client->sock->socket_fd);
            log_debug("Accepted a client connection\n");
        } else {
            mbedtls_net_context tmp;
            mbedtls_net_init(&tmp);
            mbedtls_net_accept(&srv, &tmp, NULL, 0, NULL);
            mbedtls_net_free(&tmp);
        }
    }
    // The return will never be reached
    return 0;
}
