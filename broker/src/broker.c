#include <string.h>

#include <mbedtls/ssl.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

#include <wslay/wslay.h>
#include <wslay_event.h>

#include "broker/msg/msg_handler.h"
#include "broker/net/server.h"
#include "broker/handshake.h"
#include "broker/config.h"
#include "broker/data/data.h"
#include "broker/sys/sys.h"

#define LOG_TAG "broker"
#include <dslink/log.h>
#include <dslink/utils.h>
#include <dslink/socket_private.h>
#include <dslink/err.h>
#include "broker/net/ws.h"

#define CONN_RESP "HTTP/1.1 200 OK\r\n" \
                    "Connection: close\r\n" \
                    "Content-Length: %d\r\n" \
                    "\r\n%s\r\n"

#define WS_RESP "HTTP/1.1 101 Switching Protocols\r\n" \
                    "Upgrade: websocket\r\n" \
                    "Connection: Upgrade\r\n" \
                    "Sec-WebSocket-Accept: %s\r\n\r\n"

static
void close_link(RemoteDSLink *link) {
    dslink_socket_close_nofree(link->socket);
    log_info("DSLink `%s` has disconnected\n", (char *) link->dsId->data);
    ref_t *ref = dslink_map_get(link->broker->downstream->children, (void *) link->name);
    broker_remote_dslink_free(link);
    // it's possible that free link still rely on node->link to close related streams
    // so link need to be freed before disconnected from node
    if (ref) {
        DownstreamNode *node = ref->data;
        broker_dslink_disconnect(node);
    }

    dslink_free(link);
}

static
int generate_accept_key(const char *buf, size_t bufLen,
                        char *out, size_t outLen) {
    char data[256];
    memset(data, 0, sizeof(data));
    int len = snprintf(data, sizeof(data), "%.*s%s", (int) bufLen, buf,
                          "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    unsigned char sha1[20];
    mbedtls_sha1((unsigned char *) data, (size_t) len, sha1);
    return mbedtls_base64_encode((unsigned char *) out, outLen,
                                 &outLen, sha1, sizeof(sha1));
}

static
ssize_t want_read_cb(wslay_event_context_ptr ctx,
                     uint8_t *buf, size_t len,
                     int flags, void *user_data) {
    (void) flags;

    RemoteDSLink *link = user_data;
    int ret = dslink_socket_read(link->socket, (char *) buf, len);
    if (ret == 0) {
        link->pendingClose = 1;
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

    RemoteDSLink *link = user_data;
    int written = dslink_socket_write(link->socket, (char *) data, len);
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
    RemoteDSLink *link = user_data;
    if (arg->opcode == WSLAY_TEXT_FRAME) {
        if (arg->msg_length == 2
            && arg->msg[0] == '{'
            && arg->msg[1] == '}') {
            broker_ws_send(link, "{}");
            return;
        }

        json_error_t err;
        json_t *data = json_loadb((char *) arg->msg,
                                  arg->msg_length, 0, &err);
        if (!data) {
            return;
        }
        log_debug("Received data from %s: %.*s\n", (char *) link->dsId->data,
                  (int) arg->msg_length, arg->msg);

        broker_msg_handle(link, data);
        json_decref(data);
    } else if (arg->opcode == WSLAY_CONNECTION_CLOSE) {
        link->pendingClose = 1;
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
    int len = snprintf(buf, sizeof(buf) - 1,
                       CONN_RESP, (int) strlen(data), data);
    buf[len] = '\0';
    dslink_free(data);
    dslink_socket_write(sock, buf, (size_t) len);

exit:
    return;
}

void broker_send_ws_init(Socket *sock, const char *accept) {
    char buf[1024];
    int bLen = snprintf(buf, sizeof(buf), WS_RESP, accept);
    dslink_socket_write(sock, buf, (size_t) bLen);
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

    static const struct wslay_event_callbacks cb = {
            want_read_cb,  // wslay_event_recv_callback
            want_write_cb, // wslay_event_send_callback
            NULL,          // wslay_event_genmask_callback
            NULL,          // wslay_event_on_frame_recv_start_callback
            NULL,          // wslay_event_on_frame_recv_chunk_callback
            NULL,          // wslay_event_on_frame_recv_end_callback
            on_ws_data     // wslay_event_on_msg_recv_callback
    };

    if (broker_handshake_handle_ws(broker, sock, dsId,
                                   auth, socketData, &cb, accept) != 0) {
        goto fail;
    }

    return 0;
fail:
    broker_send_bad_request(sock);
    dslink_socket_close_nofree(sock);
    return 1;
}

static
void on_data_callback(Socket *sock, void *data, void **socketData) {
    Broker *broker = data;
    RemoteDSLink *link = *socketData;
    if (link) {
        link->ws->read_enabled = 1;
        wslay_event_recv(link->ws);
        if (link->pendingClose) {
            close_link(link);
        }
        return;
    }

    HttpRequest req;
    char buf[1024];
    {
        int read = dslink_socket_read(sock, buf, sizeof(buf) - 1);
        buf[read] = '\0';
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

int broker_start() {
    int ret = 0;
    json_t *config = broker_config_get();
    if (!config) {
        ret = 1;
        return ret;
    }

    Broker broker;
    memset(&broker, 0, sizeof(Broker));
    {
        broker.root = broker_node_create("", "node");
        if (!broker.root) {
            ret = 1;
            goto exit;
        }
        broker.root->path = dslink_strdup("/");
        json_object_set_new(broker.root->meta, "$downstream",
                            json_string_nocheck("/downstream"));

        {
            BrokerNode *node = broker_node_create("defs", "static");
            if (!node) {
                ret = 1;
                goto exit;
            }

            json_object_set_new_nocheck(node->meta, "$hidden", json_true());
            if (broker_node_add(broker.root, node) != 0) {
                broker_node_free(node);
                ret = 1;
                goto exit;
            }
        }

        {
            BrokerNode *node = broker_node_create("sys", "static");
            if (!node) {
                ret = 1;
                goto exit;
            }

            if (broker_node_add(broker.root, node) != 0) {
                broker_node_free(node);
                ret = 1;
                goto exit;
            }

            if (broker_sys_node_populate(node) != 0) {
                broker_node_free(node);
                ret = 1;
                goto exit;
            }

            broker.sys = node;
        }

        {
            BrokerNode *node = broker_node_create("data", "node");
            if (!node) {
                ret = 1;
                goto exit;
            }

            if (broker_node_add(broker.root, node) != 0) {
                broker_node_free(node);
                ret = 1;
                goto exit;
            }

            if (broker_data_node_populate(node) != 0) {
                broker_node_free(node);
                ret = 1;
                goto exit;
            }
            broker.data = node;
        }

        {
            broker.downstream = broker_node_create("downstream", "node");
            if (!broker.downstream) {
                ret = 1;
                goto exit;
            }

            if (broker_node_add(broker.root, broker.downstream) != 0) {
                broker_node_free(broker.downstream);
                broker.downstream = NULL;
                ret = 1;
                goto exit;
            }
        }

        if (dslink_map_init(&broker.client_connecting,
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

    ret = broker_start_server(config, &broker,
                              on_data_callback);
exit:
    json_decref(config);
    dslink_map_free(&broker.client_connecting);
    broker_node_free(broker.root);
    return ret;
}
