#include <stdlib.h>
#include <string.h>

#include <mbedtls/base64.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/net.h>

#include <wslay/wslay.h>
#include <wslay_event.h>
#include <dslink/socket_private.h>

#include "dslink/msg/request_handler.h"
#include "dslink/msg/response_handler.h"
#include "dslink/handshake.h"
#include "dslink/ws.h"
#include "dslink/utils.h"

#include <sys/time.h>

#define LOG_TAG "ws"
#include "dslink/log.h"

#define DSLINK_WS_REQ \
    "GET %s HTTP/1.1\r\n" \
    "Host: %s:%d\r\n" \
    "Upgrade: websocket\r\n" \
    "Connection: Upgrade\r\n" \
    "Sec-WebSocket-Key: %s\r\n" \
    "Sec-WebSocket-Version: 13\r\n" \
    "\r\n"

static
int gen_mask_cb(wslay_event_context_ptr ctx,
                uint8_t *buf, size_t len,
                void *user_data) {
    (void) ctx;
    (void) user_data;
    while (len-- > 0) {
        *(buf + len) = (uint8_t) rand();
    }
    return 0;
}

static
int gen_ws_key(char *buf, size_t bufLen) {
    unsigned char rnd[12];
    {
        srand((unsigned) time(NULL));
        size_t size = sizeof(rnd);
        while (size-- > 0) {
            *(rnd + size) = (unsigned char) rand();
        }
    }

    size_t len = 0;
    if ((errno = mbedtls_base64_encode((unsigned char *) buf, bufLen,
                                       &len, rnd, sizeof(rnd))) != 0) {
        return DSLINK_CRYPT_BASE64_URL_ENCODE_ERR;
    }
    return 0;
}

static
uint32_t dslink_incr_msg(DSLink *link) {
    if (*link->msg >= INT32_MAX) {
        // Loop it around
        (*link->msg) = 0;
    }
    return ++(*link->msg);
}

static
void io_handler(uv_poll_t *poll, int status, int events) {

    (void) events;
    if (status < 0) {
        return;
    }

    DSLink* link = poll->data;
    if(!link || !link->_ws) {
        return;
    }

    if (events & UV_READABLE) {
        int stat = wslay_event_recv(link->_ws);
        if(stat != 0 ||
           link->_ws->read_enabled == 0 ||
           link->_ws->write_enabled == 0) {
            log_debug("Stopping dslink loop...\n");
            uv_stop(&link->loop);
            return;
        }
    }

    if (events & UV_WRITABLE) {
        if(!wslay_event_want_write(link->_ws)) {
            log_debug("Stopping WRITE poll on link\n");
            uv_poll_start(poll, UV_READABLE, io_handler);
        } else {
            log_debug("Enabling READ/WRITE poll on link\n");
            uv_poll_start(poll, UV_READABLE | UV_WRITABLE, io_handler);
            int stat = wslay_event_send(link->_ws);
            if(stat != 0 ||
               link->_ws->read_enabled == 0 ||
               link->_ws->write_enabled == 0) {
                log_debug("Stopping dslink loop...\n");
                uv_stop(&link->loop);
                return;
            }
        }
    }
}

int dslink_ws_send_obj(wslay_event_context_ptr ctx, json_t *obj) {
    DSLink *link = ctx->user_data;
    uint32_t msg = dslink_incr_msg(link);

    json_t *jsonMsg = json_integer(msg);
    json_object_set(obj, "msg", jsonMsg);

    char *data = json_dumps(obj, JSON_PRESERVE_ORDER);
    if (!data) {
        return DSLINK_ALLOC_ERR;
    }

    dslink_ws_send(ctx, data);
    dslink_free(data);

    json_object_del(obj, "msg");
    json_delete(jsonMsg);

    return 0;
}

static
int dslink_ws_send_internal(wslay_event_context_ptr ctx, const char *data, uint8_t resend) {
    (void) resend;
    struct wslay_event_msg msg;
    msg.msg = (const uint8_t *) data;
    msg.msg_length = strlen(data);
    msg.opcode = WSLAY_TEXT_FRAME;
    if (wslay_event_queue_msg(ctx, &msg) != 0) {
        return 1;
    }

    DSLink *link = (DSLink*)ctx->user_data;
    if(!link) {
        return 1;
    }

    // start polling on the socket, to trigger writes (We always want to poll reads)
    if(link->poll && !uv_is_closing((uv_handle_t*)link->poll)) {
        uv_poll_start(link->poll, UV_READABLE | UV_WRITABLE, io_handler);

        log_debug("Message queued to be sent: %s\n", data);
        return 0;
    }

    return -1;
}

int dslink_ws_send(struct wslay_event_context* ctx, const char* data) {
    return dslink_ws_send_internal(ctx, data, 0);
}

int dslink_handshake_connect_ws(Url *url,
                                mbedtls_ecdh_context *key,
                                const char *uri,
                                const char *tempKey,
                                const char *salt,
                                const char *dsId,
                                const char *token,
                                Socket **sock) {
    *sock = NULL;
    int ret = 0;
    unsigned char auth[90];
    if (tempKey && salt)
    if ((ret = dslink_handshake_gen_auth_key(key, tempKey, salt,
                            auth, sizeof(auth))) != 0) {
        goto exit;
    }

    char req[512];
    size_t reqLen;
    {
        char builtUri[256];
        char * encodedDsId = dslink_str_escape(dsId);
        if (tempKey && salt) {
            snprintf(builtUri, sizeof(builtUri) - 1, "%s?auth=%s&dsId=%s",
                     uri, auth, encodedDsId);
        } else {
            // trusted dslink
            snprintf(builtUri, sizeof(builtUri) - 1, "%s?dsId=%s&token=%s",
                     uri, encodedDsId, token);
        }
        dslink_free(encodedDsId);


        char wsKey[32];
        if ((ret = gen_ws_key(wsKey, sizeof(wsKey))) != 0) {
            goto exit;
        }

        reqLen = snprintf(req, sizeof(req), DSLINK_WS_REQ,
                          builtUri, url->host, url->port, wsKey);
    }

    if ((ret = dslink_socket_connect(sock, url->host,
                                     url->port, url->secure)) != 0) {
        *sock = NULL;
        goto exit;
    }

    dslink_socket_write(*sock, req, reqLen);

    char buf[1024];
    size_t len = 0;
    memset(buf, 0, sizeof(buf));
    while (len < (sizeof(buf) - 1)) {
        // Read 1 byte at a time to ensure that we don't accidentally
        // read web socket data
        int read = dslink_socket_read(*sock, buf + len, 1);
        if (read <= 0) {
            goto exit;
        }
        if (buf[len++] == '\n' && strstr(buf, "\r\n\r\n")) {
            if (!strstr(buf, "101 Switching Protocols")) {
                ret = DSLINK_HANDSHAKE_INVALID_RESPONSE;
            } if (strstr(buf, "401 Unauthorized")) {
                ret = DSLINK_HANDSHAKE_UNAUTHORIZED;
            }
            goto exit;
        }
    }

    // Failed to find the end of the HTTP response
    ret = DSLINK_HANDSHAKE_INVALID_RESPONSE;
exit:
    if (ret != 0 && *sock) {
        dslink_socket_close(*sock);
        *sock = NULL;
    }
    return ret;
}

static
ssize_t want_read_cb(wslay_event_context_ptr ctx,
                     uint8_t *buf, size_t len,
                     int flags, void *user_data) {
    (void) flags;

    DSLink *link = user_data;
    ssize_t read = -1;
    while((read = dslink_socket_read(link->_socket, (char *) buf, len)) < 0 && errno == EINTR);

    if (read == 0) {
        wslay_event_set_error(ctx, WSLAY_ERR_NO_MORE_MSG);
        return -1;
    } else if (read == DSLINK_SOCK_READ_ERR) {
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    } else if (read == DSLINK_SOCK_WOULD_BLOCK) {
        wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        return -1;
    }

    return read;
}

static
ssize_t want_write_cb(wslay_event_context_ptr ctx,
                      const uint8_t *data, size_t len,
                      int flags, void *user_data) {
    (void) flags;

    DSLink *link = user_data;

    ssize_t written = -1;
    while((written = dslink_socket_write(link->_socket, (char *) data, len)) < 0 && errno == EINTR);
    if (written < 0) {
        if (errno == EAGAIN || written == DSLINK_SOCK_WOULD_BLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
        return -1;
    }

    return written;
}

static
void recv_frame_cb(wslay_event_context_ptr ctx,
                   const struct wslay_event_on_msg_recv_arg *arg,
                   void *user_data) {

    (void) ctx;
    if (arg->opcode != WSLAY_TEXT_FRAME) {
        return;
    }

    DSLink *link = user_data;
    gettimeofday(&link->lastReceiveTime, NULL);

    json_error_t err;
    json_t *obj = json_loadb((char *) arg->msg, arg->msg_length,
                             JSON_PRESERVE_ORDER, &err);
    if (!obj) {
        log_err("Failed to parse JSON payload: %.*s\n",
                (int) arg->msg_length, arg->msg);
        goto exit;
    } else {
        log_debug("Message received: %.*s\n",
                  (int) arg->msg_length, arg->msg);
    }

    json_t *reqs = json_object_get(obj, "requests");
    if (link->is_responder && reqs) {
        size_t index;
        json_t *value;
        json_array_foreach(reqs, index, value) {
            if (dslink_request_handle(link, value) != 0) {
                log_err("Failed to handle request\n");
            }
        }
    }

    json_t *resps = json_object_get(obj, "responses");

    if (link->is_requester && resps) {
        size_t index;
        json_t *value;
        json_array_foreach(resps, index, value) {
            if (dslink_response_handle(link, value) != 0) {
                log_err("Failed to handle response\n");
            }
        }
    }

    json_t *msg = json_incref(json_object_get(obj, "msg"));

    if ((resps || reqs) && msg) {
        json_t *top = json_object();
        json_object_set_new(top, "ack", msg);
        dslink_ws_send_obj(link->_ws, top);
        json_delete(top);
    } else {
        json_decref(msg);
    }

    json_decref(obj);

    exit:
    return;
}

static
void ping_handler(uv_timer_t *timer) {
    log_debug("Pinging...\n");

    DSLink *link = timer->data;
    json_t *obj = json_object();
    dslink_ws_send_obj(link->_ws, obj);
    json_delete(obj);

    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    long time_diff = current_time.tv_sec - link->lastReceiveTime.tv_sec;
    if (time_diff >= 90) {
        log_debug("Broker didn't send any requests for 90 seconds. Stopping dslink loop...\n");
        uv_stop(&link->loop);
    }
}

static
void ping_timer_on_close(uv_handle_t *handle) {
    dslink_free(handle);
}

static
void poll_on_close(uv_handle_t *handle) {
    dslink_free(handle);
}

void dslink_handshake_handle_ws(DSLink *link, link_callback on_requester_ready_cb) {
    struct wslay_event_callbacks callbacks = {
        want_read_cb,
        want_write_cb,
        gen_mask_cb,
        NULL,
        NULL,
        NULL,
        recv_frame_cb
    };

    wslay_event_context_ptr ptr;
    if (wslay_event_context_client_init(&ptr, &callbacks, link) != 0) {
        return;
    }
    link->_ws = ptr;
    link->poll = dslink_malloc(sizeof(uv_poll_t));

    mbedtls_net_set_nonblock(&link->_socket->socket_ctx);
    {
        uv_poll_init(&link->loop, link->poll, link->_socket->socket_ctx.fd);
        link->poll->data = link;
        uv_poll_start(link->poll, UV_READABLE, io_handler);
    }

    uv_timer_t *ping = dslink_malloc(sizeof(uv_timer_t));
    {
        uv_timer_init(&link->loop, ping);
        ping->data = link;
        gettimeofday(&link->lastReceiveTime, NULL);
        uv_timer_start(ping, ping_handler, 0, 30000);
    }

    if (on_requester_ready_cb) {
        on_requester_ready_cb(link);
    }

    uv_run(&link->loop, UV_RUN_DEFAULT);

    uv_timer_stop(ping);
    uv_close((uv_handle_t *) ping, ping_timer_on_close);
    uv_close((uv_handle_t *) link->poll, poll_on_close);

    wslay_event_context_free(ptr);
    link->_ws = NULL;
}
