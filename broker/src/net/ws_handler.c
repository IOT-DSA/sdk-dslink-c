#include <wslay/wslay.h>
#include <mbedtls/ssl.h>

#define LOG_TAG "ws_handler"
#include <dslink/log.h>
#include <dslink/err.h>
#include <sys/time.h>

#include "broker/msg/msg_handler.h"
#include "broker/net/ws.h"

ssize_t broker_want_read_cb(wslay_event_context_ptr ctx,
                     uint8_t *buf, size_t len,
                     int flags, void *user_data) {
    (void) flags;

    RemoteDSLink *link = user_data;
    int ret = dslink_socket_read(link->client->sock, (char *) buf, len);
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

ssize_t broker_want_write_cb(wslay_event_context_ptr ctx,
                      const uint8_t *data, size_t len,
                      int flags, void *user_data) {
    (void) flags;

    RemoteDSLink *link = user_data;
    if (!link->client) {
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }

    int written = dslink_socket_write(link->client->sock, (char *) data, len);
    if (written < 0) {
        if (errno == EAGAIN) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else if (errno == MBEDTLS_ERR_SSL_WANT_WRITE) {
            wslay_event_set_error(ctx, WSLAY_ERR_WANT_WRITE);
        } else {
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
        return -1;
    }

    struct timeval *time = dslink_malloc(sizeof(struct timeval*));
    int ret = gettimeofday(time, NULL);

    if (ret == 0) {
        if (link->lastWriteTime) {
            dslink_free(link->lastWriteTime);
        }
        link->lastWriteTime = time;
    } else {
        dslink_free(time);
    }

    return written;
}

void broker_on_ws_data(wslay_event_context_ptr ctx,
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

const struct wslay_event_callbacks *broker_ws_callbacks() {
    static const struct wslay_event_callbacks cb = {
        broker_want_read_cb,  // wslay_event_recv_callback
        broker_want_write_cb, // wslay_event_send_callback
        NULL,          // wslay_event_genmask_callback
        NULL,          // wslay_event_on_frame_recv_start_callback
        NULL,          // wslay_event_on_frame_recv_chunk_callback
        NULL,          // wslay_event_on_frame_recv_end_callback
        broker_on_ws_data     // wslay_event_on_msg_recv_callback
    };
    return &cb;
}
