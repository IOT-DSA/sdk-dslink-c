#include <stdlib.h>
#include <string.h>

#include <mbedtls/base64.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/net.h>

#include <wslay/wslay.h>
#include <wslay_event.h>

#include "dslink/msg/request_handler.h"
#include "dslink/handshake.h"
#include "dslink/ws.h"

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

int dslink_ws_send_obj(wslay_event_context_ptr ctx, json_t *obj) {
    char *data = json_dumps(obj, JSON_PRESERVE_ORDER);
    if (!data) {
        return DSLINK_ALLOC_ERR;
    }
    dslink_ws_send(ctx, data);
    dslink_free(data);
    return 0;
}

int dslink_ws_send(wslay_event_context_ptr ctx, const char *data) {
    struct wslay_event_msg msg;
    msg.msg = (const uint8_t *) data;
    msg.msg_length = strlen(data);
    msg.opcode = WSLAY_TEXT_FRAME;
    wslay_event_queue_msg(ctx, &msg);
    wslay_event_send(ctx);
    log_debug("Message sent: %s\n", data);
    return 0;
}

int dslink_handshake_connect_ws(Url *url,
                                mbedtls_ecdh_context *key,
                                const char *uri,
                                const char *tempKey,
                                const char *salt,
                                const char *dsId,
                                Socket **sock) {
    *sock = NULL;
    int ret = 0;
    unsigned char auth[90];
    if ((ret = dslink_handshake_gen_auth_key(key, tempKey, salt,
                            auth, sizeof(auth))) != 0) {
        goto exit;
    }

    char req[512];
    size_t reqLen;
    {
        char builtUri[256];
        snprintf(builtUri, sizeof(builtUri) - 1, "%s?auth=%s&dsId=%s",
                 uri, auth, dsId);

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
    if (link->_delay == 0) {
        wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        return -1;
    }
    int read = dslink_socket_read_timeout(link->_socket,
                                          (char *) buf,len, link->_delay);
    link->_delay = 0;
    if (read == 0) {
        wslay_event_set_error(ctx, WSLAY_ERR_NO_MORE_MSG);
        return -1;
    } else if (read == DSLINK_SOCK_READ_ERR) {
        if (errno == MBEDTLS_ERR_SSL_WANT_READ
            || errno == MBEDTLS_ERR_SSL_TIMEOUT) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
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
    int written = dslink_socket_write(link->_socket, (char *) data, len);
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
void recv_frame_cb(wslay_event_context_ptr ctx,
                   const struct wslay_event_on_msg_recv_arg *arg,
                   void *user_data) {
    (void) ctx;
    if (arg->opcode != WSLAY_TEXT_FRAME) {
        return;
    }

    DSLink *link = user_data;
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
    if (reqs) {
        size_t index;
        json_t *value;
        json_array_foreach(reqs, index, value) {
            if (dslink_request_handle(link, value) != 0) {
                log_err("Failed to handle request\n");
            }
        }
    }

    json_delete(obj);
exit:
    return;
}

static
void io_handler(void *data, EventLoop *loop, uint32_t delay) {
    (void) loop;
    DSLink *link = data;
    link->_delay = delay;
    int stat = wslay_event_recv(link->_ws);
    if (stat == 0 && (link->_ws->error == WSLAY_ERR_NO_MORE_MSG
                      || link->_ws->error == 0)) {
        loop->shutdown = 1;
    }
}

static
void ping_handler(void *data, EventLoop *loop) {
    DSLink *link = data;
    dslink_ws_send(link->_ws, "{}");
    dslink_event_loop_schedd(loop, ping_handler, link, 30000);
}

void dslink_handshake_handle_ws(DSLink *link) {
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

    dslink_event_loop_init(&link->loop, io_handler, link);
    dslink_event_loop_sched(&link->loop, ping_handler, link);
    dslink_event_loop_process(&link->loop);

    dslink_event_loop_free(&link->loop);
    wslay_event_context_free(ptr);
    link->_ws = NULL;
}
