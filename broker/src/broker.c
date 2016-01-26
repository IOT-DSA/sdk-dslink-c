#include <string.h>

#include <mbedtls/ssl.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

#include <wslay/wslay.h>
#include <wslay_event.h>

#include "broker/msg_handler.h"
#include "broker/net/server.h"
#include "broker/handshake.h"
#include "broker/config.h"

#define LOG_TAG "broker"
#include <dslink/log.h>
#include <dslink/utils.h>
#include <dslink/ws.h>

#define CONN_RESP "HTTP/1.1 200 OK\r\n" \
                    "Connection: close\r\n" \
                    "Content-Length: %d\r\n" \
                    "\r\n%s\r\n"

#define WS_RESP "HTTP/1.1 101 Switching Protocols\r\n" \
                    "Upgrade: websocket\r\n" \
                    "Connection: Upgrade\r\n" \
                    "Sec-WebSocket-Accept: %s\r\n\r\n"

static
void close_link(Broker *broker) {
    dslink_socket_close_nofree(broker->socket);
    if (broker->link) {
        log_info("DSLink `%s` has disconnected\n", broker->link->dsId);
        void *tmp = (void *) broker->link->dsId;
        dslink_map_remove(&broker->downstream, &tmp);
        free((void *) broker->link->dsId);
    }
}

static
int generate_accept_key(const char *buf, size_t bufLen,
                        char *out, size_t outLen) {
    char data[256];
    memset(data, 0, sizeof(data));
    size_t len = snprintf(data, sizeof(data), "%.*s%s", (int) bufLen, buf,
                          "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    unsigned char sha1[20];
    mbedtls_sha1((unsigned char *) data, len, sha1);
    return mbedtls_base64_encode((unsigned char *) out, outLen,
                                 &outLen, sha1, sizeof(sha1));
}

static
ssize_t want_read_cb(wslay_event_context_ptr ctx,
                     uint8_t *buf, size_t len,
                     int flags, void *user_data) {
    (void) flags;

    Broker *broker = user_data;
    int ret = dslink_socket_read(broker->socket, (char *) buf, len);
    if (ret == 0) {
        close_link(broker);
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    } else if (ret == DSLINK_SOCK_READ_ERR) {
        if (errno == MBEDTLS_ERR_SSL_WANT_READ) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
        return -1;
    }

    return ret;
}

static
ssize_t want_write_cb(wslay_event_context_ptr ctx,
                      const uint8_t *data, size_t len,
                      int flags, void *user_data) {
    (void) flags;

    Broker *broker = user_data;
    int written = dslink_socket_write(broker->socket, (char *) data, len);
    if (written < 0) {
        if (errno == MBEDTLS_ERR_SSL_WANT_WRITE) {
            wslay_event_set_error(ctx, WSLAY_ERR_WANT_WRITE);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
        return -1;
    }

    return written;
}

static
void on_ws_data(wslay_event_context_ptr ctx,
                const struct wslay_event_on_msg_recv_arg *arg,
                void *user_data) {
    (void) ctx;
    Broker *broker = user_data;
    if (arg->opcode == WSLAY_TEXT_FRAME) {
        json_error_t err;
        json_t *data = json_loadb((char *) arg->msg,
                                  arg->msg_length, 0, &err);
        if (!data) {
            return;
        }
        log_debug("Received Data: %.*s\n", (int) arg->msg_length, arg->msg);

        broker_handle_msg(broker, data);
        json_decref(data);
    } else if (arg->opcode == WSLAY_CONNECTION_CLOSE) {
        close_link(broker);
    }
}

static
void handle_conn(Broker *broker, HttpRequest *req, Socket *sock) {
    json_error_t err;

    json_t *body;
    {
        const char *start = strchr(req->body, '{');
        const char *end = strrchr(req->body, '}');
        if (!(start && end)) {
            goto exit;
        }
        body = json_loadb(start, end - start + 1, 0, &err);
        if (!body) {
            broker_send_internal_error(sock);
            goto exit;
        }
    }

    const char *dsId = broker_http_param_get(&req->uri, "dsId");
    if (!dsId) {
        goto exit;
    }
    json_t *resp = broker_handshake_handle_conn(broker, dsId, body);
    json_decref(body);
    if (!resp) {
        broker_send_internal_error(sock);
        goto exit;
    }

    char *data = json_dumps(resp, JSON_INDENT(2));
    json_decref(resp);
    if (!data) {
        broker_send_internal_error(sock);
        goto exit;
    }

    char buf[1024];
    size_t len = snprintf(buf, sizeof(buf), CONN_RESP, (int) strlen(data), data);
    free(data);
    dslink_socket_write(sock, buf, len);

exit:
    return;
}

static
int handle_ws(Broker *broker, HttpRequest *req,
               Socket *sock, void **socketData) {
    size_t len = 0;
    const char *key = broker_http_header_get(req->headers,
                                             "Sec-WebSocket-Key", &len);
    if (!key) {
        goto fail;
    }
    char accept[64];
    if (generate_accept_key(key, len, accept, sizeof(accept)) != 0) {
        goto fail;
    }

    const char *dsId = broker_http_param_get(&req->uri, "dsId");
    const char *auth = broker_http_param_get(&req->uri, "auth");
    if (!(dsId && auth)) {
        goto fail;
    }

    broker->socket = sock;
    if (broker_handshake_handle_ws(broker, dsId,
                                   auth, socketData) != 0) {
        goto fail;
    }

    char buf[1024];
    len = snprintf(buf, sizeof(buf), WS_RESP, accept);
    dslink_socket_write(sock, buf, len);
    dslink_ws_send(broker->ws, "{}");

    return 0;
fail:
    broker_send_bad_request(sock);
    dslink_socket_close_nofree(sock);
    return 1;
}

static
void on_data_callback(Socket *sock, void *data, void **socketData) {
    Broker *broker = data;
    broker->socket = sock;
    broker->link = *socketData;
    if (broker->link) {
        broker->ws->read_enabled = 1;
        wslay_event_recv(broker->ws);
        return;
    }

    HttpRequest req;
    {
        char buf[1024];
        memset(buf, 0, sizeof(buf));
        dslink_socket_read(sock, buf, sizeof(buf));
        broker_http_parse_req(&req, buf);
    }

    if (strcmp(req.uri.resource, "/conn") == 0) {
        if (strcmp(req.method, "POST") != 0) {
            broker_send_bad_request(sock);
            goto exit;
        }

        handle_conn(broker, &req, sock);
    } else if (strcmp(req.uri.resource, "/ws") == 0) {
        if (strcmp(req.method, "GET") != 0) {
            broker_send_bad_request(sock);
            goto exit;
        }

        handle_ws(broker, &req, sock, socketData);
        return;
    } else {
        broker_send_not_found_error(sock);
    }

exit:
    dslink_socket_close_nofree(sock);
}

int broker_init() {
    int ret = 0;
    json_t *config = broker_config_get();
    if (!config) {
        ret = 1;
        return ret;
    }

    Broker broker;
    memset(&broker, 0, sizeof(Broker));
    {
        if (dslink_map_init(&broker.client_connecting,
                        dslink_map_str_cmp,
                        dslink_map_str_key_len_cal) != 0) {
            ret = 1;
            goto exit;
        }

        if (dslink_map_init(&broker.downstream,
                        dslink_map_str_cmp,
                        dslink_map_str_key_len_cal) != 0) {
            ret = 1;
            goto exit;
        }
    }

    {
        json_t *jsonLog = json_object_get(config, "log_level");
        if (jsonLog) {
            const char *str = json_string_value(jsonLog);
            if ((ret = dslink_log_set_lvl(str)) != 0) {
                log_fatal("Invalid log level in the broker configuration\n");
                goto exit;
            }
        } else {
            log_warn("Missing `log_level` from the broker configuration\n");
        }
    }

    struct wslay_event_callbacks cb = {
        want_read_cb,  // wslay_event_recv_callback
        want_write_cb, // wslay_event_send_callback
        NULL,          // wslay_event_genmask_callback
        NULL,          // wslay_event_on_frame_recv_start_callback
        NULL,          // wslay_event_on_frame_recv_chunk_callback
        NULL,          // wslay_event_on_frame_recv_end_callback
        on_ws_data     // wslay_event_on_msg_recv_callback
    };

    wslay_event_context_ptr ws;
    if (wslay_event_context_server_init(&ws, &cb, &broker) != 0) {
        ret = 1;
        goto exit;
    }

    broker.ws = ws;
    ret = broker_start_server(config, &broker, on_data_callback);

exit:
    DSLINK_CHECKED_EXEC(json_delete, config);
    DSLINK_MAP_FREE(&broker.client_connecting, {});
    DSLINK_MAP_FREE(&broker.downstream, {});
    return ret;
}
