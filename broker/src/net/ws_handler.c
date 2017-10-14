#include <wslay/wslay.h>

#define LOG_TAG "ws_handler"
#include <dslink/log.h>
#include <dslink/err.h>
#include <sys/time.h>
#include <broker/sys/throughput.h>

#include "broker/msg/msg_handler.h"
#include "broker/net/ws.h"
#include <msgpack.h>
#include <dslink/ws.h>
#include <dslink/utils.h>

ssize_t broker_want_read_cb(wslay_event_context_ptr ctx,
                     uint8_t *buf, size_t len,
                     int flags, void *user_data) {
    (void) flags;

    RemoteDSLink *link = user_data;
    if (!link) {
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    } else if(!link->client) {
        if(link->pendingClose == 0)
            link->pendingClose = 1;
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }  else if(!link->client->sock) {
        if(link->pendingClose == 0)
            link->pendingClose = 1;
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }

    ssize_t ret = -1;
    while((ret = dslink_socket_read(link->client->sock, (char *) buf, len)) < 0 && errno == EINTR);
    if (ret == 0) {
        if(link->pendingClose == 0)
            link->pendingClose = 1;
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    } else if (ret < 0) {
        if (errno == EAGAIN || ret == DSLINK_SOCK_WOULD_BLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            if(link->pendingClose == 0)
                link->pendingClose = 1;
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
    if (!link) {
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    } else if(!link->client) {
        if(link->pendingClose == 0)
            link->pendingClose = 1;
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }  else if(!link->client->sock) {
        if(link->pendingClose == 0)
            link->pendingClose = 1;
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    }

    ssize_t written = -1;
    while((written = dslink_socket_write(link->client->sock, (char *) data, len)) < 0 && errno == EINTR);
    if (written == 0) {
        if(link->pendingClose == 0)
            link->pendingClose = 1;
        wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        return -1;
    } else if (written < 0) {
        if (errno == EAGAIN || written == DSLINK_SOCK_WOULD_BLOCK) {
            wslay_event_set_error(ctx, WSLAY_ERR_WOULDBLOCK);
        } else {
            if(link->pendingClose == 0)
                link->pendingClose = 1;
            wslay_event_set_error(ctx, WSLAY_ERR_CALLBACK_FAILURE);
        }
        return -1;
    }

    struct timeval *time = dslink_malloc(sizeof(struct timeval));
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
    if (!link) {
        return;
    }

    if (!link->lastReceiveTime) {
        link->lastReceiveTime = dslink_malloc(sizeof(struct timeval));
    }
    gettimeofday(link->lastReceiveTime, NULL);

    if (arg->opcode == WSLAY_CONNECTION_CLOSE) {
        if(link->pendingClose == 0)
            link->pendingClose = 1;
        return;
    }

    json_t *data = NULL;
    int is_recv_data_msg_pack = 0;

    if (arg->opcode == WSLAY_TEXT_FRAME) {
        json_error_t err;
        data = json_loadb((char *) arg->msg,
                          arg->msg_length, 0, &err);
    }
    else if(arg->opcode == WSLAY_BINARY_FRAME)
    {
        msgpack_unpacked msg;
        msgpack_unpacked_init(&msg);
        msgpack_unpack_next(&msg, (char *) arg->msg, arg->msg_length, NULL);

        /* prints the deserialized object. */
        msgpack_object obj = msg.data;

        data = dslink_ws_msgpack_to_json(&obj);

        is_recv_data_msg_pack = 1;
    }

    // Check whether it is ping or not
    if(data != NULL && json_object_iter(data) == NULL)
    {
        log_debug("Ping received (as %s), responding back...\n", is_recv_data_msg_pack?"msgpack":"json");
        broker_ws_send_ping(link);
        return;
    }



    if (throughput_input_needed()) {
        int receiveMessages = 0;
        if (data) {
            receiveMessages = broker_count_json_msg(data);
        }
        throughput_add_input(arg->msg_length, receiveMessages);
    }
    if (!data) {
        return;
    }

    log_debug("Received data(as %s) from %s: %s\n",
                  (is_recv_data_msg_pack==1)?"msgpack":"json",
                  (char *) link->dsId->data,
                  json_dumps(data, JSON_INDENT(0)));

    broker_msg_handle(link, data);
    json_decref(data);


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
