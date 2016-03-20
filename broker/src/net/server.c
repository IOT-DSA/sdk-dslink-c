#include <inttypes.h>
#include <string.h>

#define LOG_TAG "server"
#include <dslink/log.h>
#include <dslink/socket_private.h>
#include <dslink/mem/mem.h>
#include <uv-common.h>

#include "broker/utils.h"
#include "broker/broker.h"

struct Server {
    mbedtls_net_context srv;
    DataReadyCallback data_ready;
};

static
void broker_server_client_ready(uv_poll_t *poll,
                                int status,
                                int events) {
    (void) status;
    (void) events;

    Client *client = poll->data;
    Server *server = client->server;
    server->data_ready(client, poll->loop->data);
    if (client->sock->socket_fd.fd == -1) {
        // The callback closed the connection
        dslink_socket_free(client->sock);
        dslink_free(client);
        uv_close((uv_handle_t *) poll, broker_free_handle);
    }
}

static
void broker_server_new_client(uv_poll_t *poll,
                              int status, int events) {
    (void) status;
    (void) events;

    Server *server = poll->data;
    Client *client = dslink_calloc(1, sizeof(Client));
    if (!client) {
        goto fail;
    }

    client->server = server;
    client->sock = dslink_socket_init(0);
    if (!client->sock) {
        dslink_free(client);
        goto fail;
    }

    if (mbedtls_net_accept(&server->srv, &client->sock->socket_fd,
                           NULL, 0, NULL) != 0) {
        log_warn("Failed to accept a client connection\n");
        goto fail_poll_setup;
    }

    uv_poll_t *clientPoll = dslink_malloc(sizeof(uv_poll_t));
    if (!clientPoll) {
        goto fail_poll_setup;
    }

    uv_loop_t *loop = poll->loop;
    if (uv_poll_init(loop, clientPoll,
                     client->sock->socket_fd.fd) != 0) {
        dslink_free(clientPoll);
        goto fail_poll_setup;
    }

    clientPoll->data = client;
    client->poll = clientPoll;
    uv_poll_start(clientPoll, UV_READABLE, broker_server_client_ready);

    log_debug("Accepted a client connection\n");
    return;
fail:
    {
        mbedtls_net_context tmp;
        mbedtls_net_init(&tmp);
        mbedtls_net_accept(&server->srv, &tmp, NULL, 0, NULL);
        mbedtls_net_free(&tmp);
    }
    return;
fail_poll_setup:
    dslink_socket_free(client->sock);
    dslink_free(client);
}

static
int start_http_server(Server *server, const char *host,
                       const char *port, uv_loop_t *loop,
                       uv_poll_t *poll) {
    if (mbedtls_net_bind(&server->srv, host, port, MBEDTLS_NET_PROTO_TCP) != 0) {
        log_fatal("Failed to bind to %s:%s\n", host, port);
        return 0;
    } else {
        log_info("HTTP server bound to %s:%s\n", host, port);
    }

    uv_poll_init(loop, poll, server->srv.fd);
    poll->data = server;
    uv_poll_start(poll, UV_READABLE, broker_server_new_client);
    return 1;
}

static
void stop_server_handler(uv_signal_t* handle, int signum) {
    const char *sig;
    if (signum == SIGINT) {
        sig = "SIGINT";
    } else if (signum == SIGTERM) {
        sig = "SIGTERM";
    } else {
        // Ignore unknown signal
        return;
    }
    log_warn("Received %s, gracefully terminating broker...\n", sig);

    Broker* broker = handle->loop->data;
    broker_stop(broker);
    uv_stop(handle->loop);
}

int broker_start_server(json_t *config, void *data,
                        DataReadyCallback cb) {
    json_incref(config);

    const char *httpHost = NULL;
    char httpPort[8];
    memset(httpPort, 0, sizeof(httpPort));
    {
        json_t *http = json_object_get(config, "http");
        if (http) {
            json_t *enabled = json_object_get(http, "enabled");
            if (!(enabled && json_boolean_value(enabled))) {
                json_decref(config);
                return 0;
            }
            httpHost = json_string_value(json_object_get(http, "host"));

            json_t *jsonPort = json_object_get(http, "port");
            if (jsonPort) {
                json_int_t p = json_integer_value(jsonPort);
                int len = snprintf(httpPort, sizeof(httpPort) - 1,
                                   "%" JSON_INTEGER_FORMAT, p);
                httpPort[len] = '\0';
            }
        }
    }

    uv_loop_t loop;
    uv_loop_init(&loop);
    loop.data = data;

    int httpActive = 0;
    Server httpServer;
    uv_poll_t httpPoll;
    if (httpHost && httpPort[0] != '\0') {
        mbedtls_net_init(&httpServer.srv);
        httpServer.data_ready = cb;

        httpActive = start_http_server(&httpServer, httpHost, httpPort,
                                       &loop, &httpPoll);
    }

    uv_signal_t sigInt;
    uv_signal_init(&loop, &sigInt);
    uv_signal_start(&sigInt, stop_server_handler, SIGINT);

    uv_signal_t sigTerm;
    uv_signal_init(&loop, &sigTerm);
    uv_signal_start(&sigTerm, stop_server_handler, SIGTERM);

    if (httpActive) {
        uv_run(&loop, UV_RUN_DEFAULT);
    }

    uv_signal_stop(&sigInt);
    uv_signal_stop(&sigTerm);

    if (httpActive) {
        uv_poll_stop(&httpPoll);
    }
    uv_loop_close(&loop);
#if defined(__unix__) || defined(__APPLE__)
    uv__free(loop.watchers);
#endif

    json_decref(config);
    return 0;
}
