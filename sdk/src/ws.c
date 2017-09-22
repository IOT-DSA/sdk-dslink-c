#include <stdlib.h>
#include <string.h>

#include <wslay/wslay.h>
#include <wslay_event.h>
#include <dslink/socket_private.h>
#include <dslink/base64_url.h>
#include <msgpack/object.h>

#include "dslink/msg/request_handler.h"
#include "dslink/msg/response_handler.h"
#include "dslink/handshake.h"
#include "dslink/ws.h"
#include "dslink/utils.h"

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
    if ((errno = dslink_base64_encode((unsigned char *) buf, bufLen,
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
        if(stat != 0) {
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
            if(stat != 0) {
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

    log_debug("Message(as %s) is trying sent: %s\n",
                  (link->is_msgpack==1)?"msgpack":"json",
                  json_dumps(obj,JSON_INDENT(0)));

    // DECODE OBJ
    char* data = NULL;
    int len;
    int opcode;

    if(link->is_msgpack)
    {
        msgpack_sbuffer* buff = dslink_ws_json_to_msgpack(obj);
        data = malloc(buff->size);
        len = buff->size;
        memcpy(data, buff->data, len);
        msgpack_sbuffer_free(buff);
        opcode = WSLAY_BINARY_FRAME;
    }
    else
    {
        data = json_dumps(obj, JSON_PRESERVE_ORDER);
        len = strlen(data);
        opcode = WSLAY_TEXT_FRAME;
    }

    json_object_del(obj, "msg");
    json_delete(jsonMsg);

    if (!data) {
        return DSLINK_ALLOC_ERR;
    }

    dslink_ws_send(ctx, data, len, opcode);
    dslink_free(data);

    return 0;
}

int dslink_ws_send_ping(wslay_event_context_ptr ctx) {
    DSLink *link = ctx->user_data;

    json_t *obj = json_object();

    log_debug("Message (ping) (as %s) is trying sent\n",
              (link->is_msgpack==1)?"msgpack":"json");

    // DECODE OBJ
    char* data = NULL;
    int len;
    int opcode;

    if(link->is_msgpack)
    {
        msgpack_sbuffer* buff = dslink_ws_json_to_msgpack(obj);
        data = malloc(buff->size);
        len = buff->size;
        memcpy(data, buff->data, len);
        msgpack_sbuffer_free(buff);
        opcode = WSLAY_BINARY_FRAME;
    }
    else
    {
        data = json_dumps(obj, JSON_PRESERVE_ORDER);
        len = strlen(data);
        opcode = WSLAY_TEXT_FRAME;
    }

    json_delete(obj);

    if (!data) {
        return DSLINK_ALLOC_ERR;
    }

    dslink_ws_send(ctx, data, len, opcode);
    dslink_free(data);

    return 0;
}

static
int dslink_ws_send_internal(wslay_event_context_ptr ctx,
                            const char *data, const int len, int opcode,
                            uint8_t resend) {
    (void) resend;
    struct wslay_event_msg msg;
    msg.msg = (const uint8_t *) data;
    msg.msg_length = len;
    msg.opcode = opcode;

    DSLink *link = (DSLink*)ctx->user_data;
    if(!link) {
        return 1;
    }

#ifdef DSLINK_WS_SEND_THREADED
    uv_sem_wait(&link->ws_queue_sem);
#endif
    if (wslay_event_queue_msg(ctx, &msg) != 0) {
        return 1;
    }
#ifdef DSLINK_WS_SEND_THREADED
    uv_sem_post(&link->ws_send_sem);
#else
    // start polling on the socket, to trigger writes (We always want to poll reads)
    uv_poll_start(link->poll, UV_READABLE | UV_WRITABLE, io_handler);
#endif

    log_debug("Message(%s) queued to be sent: %s\n", (opcode==WSLAY_TEXT_FRAME)?"text":"binary", data);
    return 0;
}

int dslink_ws_send(struct wslay_event_context* ctx, const char* data, const int len, const int opcode) {
    return dslink_ws_send_internal(ctx, data, len, opcode, 0);
}

int dslink_handshake_connect_ws(Url *url,
                                dslink_ecdh_context *key,
                                const char *uri,
                                const char *tempKey,
                                const char *salt,
                                const char *dsId,
                                const char *token,
                                const char *format,
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
            snprintf(builtUri, sizeof(builtUri) - 1, "%s?auth=%s&dsId=%s&format=%s",
                     uri, auth, encodedDsId, format);
        } else {
            // trusted dslink
            snprintf(builtUri, sizeof(builtUri) - 1, "%s?dsId=%s&token=%s&format=%s",
                     uri, encodedDsId, token, format);
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
    DSLink *link = user_data;

    json_t *obj = NULL;
    int is_recv_data_msg_pack = 0;

    if (arg->opcode == WSLAY_TEXT_FRAME) {
        json_error_t err;
        obj = json_loadb((char *) arg->msg, arg->msg_length,
                         JSON_PRESERVE_ORDER, &err);
    }
    else if(arg->opcode == WSLAY_BINARY_FRAME){
        msgpack_unpacked msg;
        msgpack_unpacked_init(&msg);
        msgpack_unpack_next(&msg, (char *) arg->msg, arg->msg_length, NULL);

        /* prints the deserialized object. */
        msgpack_object obj_msgpack = msg.data;

        obj = dslink_ws_msgpack_to_json(&obj_msgpack);
        is_recv_data_msg_pack = 1;
    }
    else {
        return;
    }


    if (!obj) {
        log_err("Failed to parse JSON payload: %.*s\n",
                (int) arg->msg_length, arg->msg);
        goto exit;
    } else {
        log_debug("Message(as %s) received: %s\n",
                  (is_recv_data_msg_pack==1)?"msgpack":"json",
                  json_dumps(obj, JSON_INDENT(0)));
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
    dslink_ws_send_ping(link->_ws);
}

static
void ping_timer_on_close(uv_handle_t *handle) {
    dslink_free(handle);
}

static
void poll_on_close(uv_handle_t *handle) {
    dslink_free(handle);
}

#ifdef DSLINK_WS_SEND_THREADED
void dslink_send_ws_thread(void *arg) {

    int ret;
    DSLink *link = (DSLink*)arg;
    while(1) {
        uv_sem_wait(&link->ws_send_sem);

        if(link->closingSendThread ==1) {
            log_debug("Closing ws send thread\n");
            break;
        }

        ret = wslay_event_send(link->_ws);
        if (ret != 0) {
            log_debug("Send error in thread: %d\n",ret);
        } else {
            log_debug("Message sent: %d\n",ret);
        }
        uv_sem_post(&link->ws_queue_sem);
    }
}
#endif

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

    dslink_socket_set_nonblock(link->_socket);
    {
        uv_poll_init(&link->loop, link->poll, link->_socket->fd);
        link->poll->data = link;
        uv_poll_start(link->poll, UV_READABLE, io_handler);
    }

    uv_timer_t *ping = dslink_malloc(sizeof(uv_timer_t));
    {
        uv_timer_init(&link->loop, ping);
        ping->data = link;
        ping->close_cb = ping_timer_on_close;
        uv_timer_start(ping, ping_handler, 0, 30000);
    }

#ifdef DSLINK_WS_SEND_THREADED
    link->closingSendThread = 0;
    uv_sem_init(&link->ws_send_sem,0);
    uv_sem_init(&link->ws_queue_sem,1);
    uv_thread_t send_ws_thread_id;
    uv_thread_create(&send_ws_thread_id, dslink_send_ws_thread, link);
#endif

    if (on_requester_ready_cb) {
        on_requester_ready_cb(link);
    }
    
    uv_run(&link->loop, UV_RUN_DEFAULT);

    uv_timer_stop(ping);
    uv_close((uv_handle_t *) ping, ping_timer_on_close);
    uv_close((uv_handle_t *) link->poll, poll_on_close);

#ifdef DSLINK_WS_SEND_THREADED
    link->closingSendThread = 1;
    uv_sem_post(&link->ws_send_sem);
    uv_thread_join(&send_ws_thread_id);
    uv_sem_destroy(&link->ws_send_sem);
    uv_sem_destroy(&link->ws_queue_sem);
#endif

    wslay_event_context_free(ptr);
    link->_ws = NULL;
}

int sync_json_to_msg_pack(json_t *json_obj, msgpack_packer* pk)
{
    char* buf;
    size_t buf_len = 0;

    switch(json_obj->type)
    {
        case JSON_OBJECT:
            msgpack_pack_map(pk, json_object_size(json_obj));

            const char *key;
            json_t *value;

            void *iter = json_object_iter(json_obj);
            while(iter)
            {
                key = json_object_iter_key(iter);
                value = json_object_iter_value(iter);

                msgpack_pack_str(pk, strlen(key));
                msgpack_pack_str_body(pk, key, strlen(key));

                if(sync_json_to_msg_pack(value, pk) != 1)
                    return 0;

                iter = json_object_iter_next(json_obj, iter);
            }

            break;
        case JSON_ARRAY:
            msgpack_pack_array(pk, json_array_size(json_obj));
            for(size_t i = 0; i < json_array_size(json_obj); i++)
            {
                if(sync_json_to_msg_pack(json_array_get(json_obj, i), pk) != 1)
                    return 0;
            }
            break;
        case JSON_BINARY:
            buf_len = json_binary_length_raw(json_obj);
            buf = (char*) malloc(buf_len);

            buf_len = json_binary_value(json_obj, buf);

            msgpack_pack_bin(pk, buf_len);
            msgpack_pack_bin_body(pk, buf, buf_len);

            free(buf);
            break;
        case JSON_STRING:
            msgpack_pack_str(pk, json_string_length(json_obj));
            msgpack_pack_str_body(pk, json_string_value(json_obj), json_string_length(json_obj));
            break;
        case JSON_INTEGER:
            msgpack_pack_int(pk, json_integer_value(json_obj));
            break;
        case JSON_REAL:
            msgpack_pack_double(pk, json_real_value(json_obj));
            break;
        case JSON_TRUE:
            msgpack_pack_true(pk);
            break;
        case JSON_FALSE:
            msgpack_pack_false(pk);
            break;
        case JSON_NULL :
            msgpack_pack_nil(pk);
            break;
    }

    return 1;
}

msgpack_sbuffer* dslink_ws_json_to_msgpack(json_t *json_obj)
{
    msgpack_sbuffer* buffer = msgpack_sbuffer_new();
    msgpack_packer* pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);

    if( sync_json_to_msg_pack(json_obj, pk) != 1)
        goto ERROR;

    EXIT:
    msgpack_packer_free(pk);
    return buffer;

    ERROR:
    log_fatal("Cannot convert to msg_pack\n")
    msgpack_sbuffer_free(buffer);
    buffer = NULL;
    goto EXIT;
}



json_t* dslink_ws_msgpack_to_json(msgpack_object* msg_obj)
{
    json_t* json_obj = NULL;
    json_t* temp = NULL;

    char* text;

    switch(msg_obj->type)
    {
        case MSGPACK_OBJECT_NIL:
            json_obj = json_null();
            break;
        case MSGPACK_OBJECT_BOOLEAN:
            json_obj = json_boolean(msg_obj->via.boolean);
            break;
        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            json_obj = json_integer(msg_obj->via.u64);
            break;
        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            json_obj = json_integer(msg_obj->via.i64);
            break;
        case MSGPACK_OBJECT_FLOAT32:
            json_obj = json_real(msg_obj->via.f64);
            break;
        case MSGPACK_OBJECT_FLOAT:
            json_obj = json_real(msg_obj->via.f64);
            break;
        case MSGPACK_OBJECT_STR:
            json_obj = json_stringn_nocheck(msg_obj->via.str.ptr, msg_obj->via.str.size);
            break;
        case MSGPACK_OBJECT_ARRAY:
            json_obj = json_array();
            for(uint32_t i = 0; i < msg_obj->via.array.size; i++)
            {
                temp = dslink_ws_msgpack_to_json(&msg_obj->via.array.ptr[i]);
                if(temp == NULL)
                    goto ERROR;

                json_array_append(json_obj, temp);
            }
            break;
        case MSGPACK_OBJECT_MAP:
            json_obj = json_object();

            for(uint32_t i = 0; i < msg_obj->via.map.size; i++)
            {
                msgpack_object_kv* kv = &msg_obj->via.map.ptr[i];
                if(kv->key.type != MSGPACK_OBJECT_STR)
                    goto ERROR;

                temp = dslink_ws_msgpack_to_json(&kv->val);
                if(temp == NULL)
                    goto ERROR;

                text = malloc(kv->key.via.str.size + 1);
                memcpy(text, kv->key.via.str.ptr, kv->key.via.str.size);
                text[kv->key.via.str.size] = '\0';
                json_object_set_nocheck(json_obj, text, temp);
                free(text);
            }

            break;
        case MSGPACK_OBJECT_BIN:
            json_obj = json_binaryn_nocheck(msg_obj->via.bin.ptr, msg_obj->via.bin.size);
            break;
        case MSGPACK_OBJECT_EXT:
            log_fatal("Cannot convert json BECAUSE EXT NOT IMPLEMENTED\n");
            goto ERROR;
            break;
    }

    EXIT:
    return json_obj;

    ERROR:
    if(json_obj != NULL)
        json_decref(json_obj);

    json_obj = NULL;
    goto EXIT;
}