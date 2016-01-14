#include <sys/select.h>
#include <inttypes.h>
#include <string.h>

#define LOG_TAG "server"
#include <dslink/log.h>
#include <dslink/socket_private.h>
#include <dslink/socket.h>

#include "broker/server.h"
#define MAX_CLIENTS 2

int dslink_broker_start_server(json_t *config, HttpCallback cb) {
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
                snprintf(buf, sizeof(buf), "%" PRIu32, p);
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

    Socket *clients[MAX_CLIENTS];
    memset(clients, 0, sizeof(clients));

    while (1) {
        fd_set readFds;
        FD_SET(srv.fd, &readFds);
        int maxFd = srv.fd;
        for (int i = 0; i < MAX_CLIENTS; ++i) {
            Socket *client = clients[i];
            if (client) {
                FD_SET(client->socket_fd.fd, &readFds);
                if (client->socket_fd.fd > maxFd) {
                    maxFd = client->socket_fd.fd;
                }
            }
        }

        int ready = select(maxFd + 1, &readFds, NULL, NULL, NULL);
        if (ready < 0) {
            break;
        }

        for (int i = 0; i < MAX_CLIENTS; ++i) {
            Socket *client = clients[i];
            if (client == NULL || !FD_ISSET(client->socket_fd.fd, &readFds)) {
                continue;
            }

            char buf[1024];
            int read = dslink_socket_read(client, buf, sizeof(buf) - 1);
            if (read <= 0) {
                clients[i] = NULL;
                dslink_socket_close(client);
                log_info("Connection closed\n");
                continue;
            }
            buf[read] = '\0';

            HttpRequest req;
            dslink_http_parse_req(&req, buf);
            if (req.method != NULL) {
                cb(&req, client);
            } else {
                // Invalid HTTP request
                dslink_socket_close_nofree(client);
            }
            if (client->socket_fd.fd == -1) {
                // The callback closed the connection
                clients[i] = NULL;
                dslink_socket_free(client);
            }
        }

        if (!FD_ISSET(srv.fd, &readFds)) {
            continue;
        }

        int i = 0;
        Socket *client = NULL;
        for (; i < MAX_CLIENTS; ++i) {
            Socket *tmp = clients[i];
            if (tmp == NULL) {
                client = clients[i] = dslink_socket_init(0);
                break;
            }
        }
        if (client) {
            if (mbedtls_net_accept(&srv, &client->socket_fd,
                                   NULL, 0, NULL) != 0) {
                log_warn("Failed to accept connection\n");
                dslink_socket_close(client);
                clients[i] = NULL;
                continue;
            }

            log_info("Accepted a connection\n");
        } else {
            mbedtls_net_context tmp;
            mbedtls_net_init(&tmp);
            mbedtls_net_accept(&srv, &tmp, NULL, 0, NULL);
            mbedtls_net_free(&tmp);
        }
    }

    for (int i = 0; i < MAX_CLIENTS; ++i) {
        Socket *client = clients[i];
        if (client) {
            clients[i] = NULL;
            dslink_socket_close(client);
        }
    }
    mbedtls_net_free(&srv);
    json_decref(config);
    return 0;
}
