#include <string.h>

#define LOG_TAG "ws"
#include <dslink/log.h>
#include <dslink/err.h>
#include <wslay_event.h>

#include "broker/sys/throughput.h"
#include "broker/remote_dslink.h"
#include "broker/net/ws.h"

#include <dslink/base64_url.h>
#include <dslink/crypto.h>

#include <msgpack.h>
#include <dslink/ws.h>
#include <dslink/utils.h>

#include <broker/broker.h>

#define BROKER_WS_RESP  "HTTP/1.1 101 Switching Protocols\r\n" \
                        "Upgrade: websocket\r\n" \
                        "Connection: Upgrade\r\n" \
                        "Sec-WebSocket-Accept: %s\r\n\r\n"

void broker_ws_send_init(Socket *sock, const char *accept) {
    char buf[1024];
    int bLen = snprintf(buf, sizeof(buf), BROKER_WS_RESP, accept);
    dslink_socket_write(sock, buf, (size_t) bLen);
}
int broker_ws_send_ping(RemoteDSLink *link) {


    log_debug("Message (Ping)(as %s) is trying sent to %s\n",
              (link->is_msgpack==1)?"msgpack":"json",
              (char *) link->dsId->data);

    json_t *obj = json_object();
    if(broker_ws_send_obj(link, obj) < 0)
    {
        log_err("Message (Ping)(as %s) is failed sent to %s\n",
                (link->is_msgpack==1)?"msgpack":"json",
                (char *) link->dsId->data);
    }
    json_decref(obj);
    return 0;
}

int broker_ws_send_str(RemoteDSLink *link, const char *str, int opcode) {
    return broker_ws_send(link, str, strlen(str), opcode);
}

// TODO: check it is old code from merge
int broker_ws_send(RemoteDSLink *link, const char *data, int len, int opcode) {
    if (!link->ws || !link->client) {
        return -1;
    }

#ifdef BROKER_WS_SEND_THREAD_MODE
    uv_sem_wait(&link->broker->ws_queue_sem);
    if(link->broker->closing_send_thread == 1) {
        uv_sem_post(&link->broker->ws_queue_sem);
        log_debug("Broker in closing state, not able to send ws\n");
        return -1;
    }
#endif

    struct wslay_event_msg msg;
    msg.msg = (const uint8_t *) data;
    msg.msg_length = len;
    msg.opcode = opcode;

    wslay_event_queue_msg(link->ws, &msg);


#ifdef BROKER_WS_SEND_THREAD_MODE
#ifdef BROKER_WS_SEND_HYBRID_MODE
    if((link->ws->queued_msg_count > 100) ) {
        link->broker->currLink = link;
        if(link->client->poll) {
            uv_poll_start(link->client->poll, UV_READABLE, link->client->poll_cb);
        }
        uv_sem_post(&link->broker->ws_send_sem);
    } else {
        if(link->client->poll) {
            uv_poll_start(link->client->poll, UV_READABLE | UV_WRITABLE, link->client->poll_cb);
        }
        uv_sem_post(&link->broker->ws_queue_sem);
    }
#else
    link->broker->currLink = link;
    log_debug("Message(%s) queued to be sent to %s: %.*s\n",
              (opcode==WSLAY_TEXT_FRAME)?"text":"binary",
              (char *) link->dsId->data, len, data);
    uv_sem_post(&link->broker->ws_send_sem);
#endif
    return (int)msg.msg_length;
#else
    (void)droppable;
    if (link->client->poll && !uv_is_closing((uv_handle_t*)link->client->poll)) {
#ifdef BROKER_WS_DIRECT_SEND
        int ret = wslay_event_send(link->ws);
        if (ret != 0) {
            log_debug("Send error %d\n", ret);
        } else {
            log_debug("Message(%s) sent to %s: %s\n",
                      (opcode==WSLAY_TEXT_FRAME)?"text":"binary",
                      (char *) link->dsId->data, data);
            return (int)msg.msg_length;
        }
#else
        uv_poll_start(link->client->poll, UV_READABLE | UV_WRITABLE, link->client->poll_cb);
        log_debug("Message queued to be sent to %s: %s\n", link->name, data);
        return (int) msg.msg_length;
#endif
    }
    return -1;
#endif
}

int broker_ws_send_obj(RemoteDSLink *link, json_t *obj) {
    uint32_t id = ++link->msgId;
    //that value : 0x7FFFFFFF
    if(link->msgId == 2147483647) {
        link->msgId = 0;
    }
    json_object_set_new_nocheck(obj, "msg", json_integer(id));

    // DECODE OBJ
    char* data = NULL;
    int len;
    int opcode;

    LOG_LVL_CHK(LOG_LVL_DEBUG) {
        char *tempDump = json_dumps(obj, JSON_INDENT(0));
        log_debug("Message(as %s) is trying sent to %s: %s\n",
                  (link->is_msgpack == 1) ? "msgpack" : "json",
                  (char *) link->dsId->data,
                  tempDump);
        dslink_free(tempDump);
    }

    if(link->is_msgpack) {
        msgpack_sbuffer* buff = dslink_ws_json_to_msgpack(obj);
        data = malloc(buff->size);
        len = buff->size;
        memcpy(data, buff->data, len);
        msgpack_sbuffer_free(buff);
        opcode = WSLAY_BINARY_FRAME;
    }
    else {
        data = json_dumps(obj, JSON_PRESERVE_ORDER | JSON_COMPACT);
        len = strlen(data);
        opcode = WSLAY_TEXT_FRAME;
    }

    json_object_del(obj, "msg");

    if (!data) {
        return DSLINK_ALLOC_ERR;
    }

    int sentBytes = broker_ws_send(link, data, len, opcode);

    if(sentBytes == -1)
    {
        LOG_LVL_CHK(LOG_LVL_DEBUG) {
            char *tempDump = json_dumps(obj, JSON_INDENT(0));
            log_err("Message(as %s) is failed sent to %s: %s\n",
                    (link->is_msgpack == 1) ? "msgpack" : "json",
                    (char *) link->dsId->data,
                    tempDump);
            dslink_free(tempDump);
        }
    }

    if (throughput_output_needed()) {
        int sentMessages = broker_count_json_msg(obj);
        throughput_add_output(sentBytes, sentMessages);
    }
    dslink_free(data);
    return id;
}


int broker_ws_generate_accept_key(const char *buf, size_t bufLen,
                                  char *out, size_t outLen) {
    char data[256];
    memset(data, 0, sizeof(data));
    int len = snprintf(data, sizeof(data), "%.*s%s", (int) bufLen, buf,
                       "258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    unsigned char sha1[20];
    dslink_crypto_sha1((unsigned char *) data, (size_t) len, sha1);
    return dslink_base64_encode((unsigned char *) out, outLen,
                                 &outLen, sha1, sizeof(sha1));
}


int broker_count_json_msg(json_t *json) {
    int messages = 0;
    json_t * requests = json_object_get(json, "requests");
    json_t * responses = json_object_get(json, "responses");
    if (json_is_array(requests)) {
        messages += json_array_size(requests);
    }
    if (json_is_array(responses)) {
        size_t  idx;
        json_t * value;
        json_array_foreach(responses, idx, value) {
            json_t *updates = json_object_get(value, "updates");
            size_t updatesSize = json_array_size(updates);
            if (updatesSize > 0) {
                messages += updatesSize;
            } else {
                messages ++;
            }
        }
    }
    return messages;
}

#ifdef BROKER_WS_SEND_THREAD_MODE
void broker_send_ws_thread(void *arg) {
    Broker *broker = (Broker *) arg;
    while (1) {
#if defined(BROKER_CLOSE_LINK_SEM2)
        uv_sem_wait(&broker->ws_send_sem);
        if (broker->closing_send_thread == 1) {
            log_debug("Closing ws send thread\n");
            uv_sem_post(&broker->ws_queue_sem);
            break;
        }
        if(!broker->currLink || uv_sem_trywait(&broker->currLink->close_sem) != 0) {
            uv_sem_post(&broker->ws_queue_sem);
            continue;
        }
#else
        uv_sem_wait(&broker->ws_send_sem);
        if (broker->closing_send_thread == 1) {
            log_debug("Closing ws send thread\n");
            break;
        }
#endif
        if(broker->currLink && (broker->currLink->pendingClose == 0) &&
           !(wslay_event_send(broker->currLink->ws))) {
            log_debug("Message sent: %s\n", broker->currLink->name);
        } else {
            log_debug("Send error in thread\n");
            uv_sem_post(&broker->ws_queue_sem);
#if defined(BROKER_CLOSE_LINK_SEM2)
            goto cont;
#else
            continue;
#endif
        }
#ifdef BROKER_WS_SEND_HYBRID_MODE
        if (wslay_event_want_write(broker->currLink->ws)) {
                uv_poll_start(broker->currLink->client->poll, UV_READABLE | UV_WRITABLE, broker->currLink->client->poll_cb);
            }
            else {
                uv_poll_start(broker->currLink->client->poll, UV_READABLE, broker->currLink->client->poll_cb);
                uv_sem_post(&broker->ws_queue_sem);
            }
#else
        if (broker->currLink && (broker->currLink->pendingClose == 0) &&
            wslay_event_want_write(broker->currLink->ws)) {
            uv_sem_post(&broker->ws_send_sem);
        } else {
            uv_sem_post(&broker->ws_queue_sem);
        }
#endif

#if defined(BROKER_CLOSE_LINK_SEM2)
cont:
        uv_sem_post(&broker->currLink->close_sem);
#endif
    }
}
#endif

