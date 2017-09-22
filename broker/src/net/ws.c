#include <string.h>
#include <mbedtls/sha1.h>
#include <mbedtls/base64.h>

#define LOG_TAG "ws"
#include <dslink/log.h>
#include <dslink/err.h>
#include <broker/sys/throughput.h>
#include <wslay_event.h>

#include "broker/remote_dslink.h"
#include "broker/net/ws.h"
#include "broker/net/server.h"

#include <dslink/utils.h>
#include <broker/broker.h>

#ifdef BROKER_WS_SEND_THREAD_MODE
#include "broker/broker.h"
#endif


#define BROKER_WS_RESP "HTTP/1.1 101 Switching Protocols\r\n" \
                            "Upgrade: websocket\r\n" \
                            "Connection: Upgrade\r\n" \
                            "Sec-WebSocket-Accept: %s\r\n\r\n"

void broker_ws_send_init(Socket *sock, const char *accept) {
    char buf[1024];
    int bLen = snprintf(buf, sizeof(buf), BROKER_WS_RESP, accept);
    dslink_socket_write(sock, buf, (size_t) bLen);
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
int broker_ws_send_obj(RemoteDSLink *link, json_t *obj, int droppable) {
    ++link->msgId;
    json_object_set_new_nocheck(obj, "msg", json_integer(link->msgId));
    char *data = json_dumps(obj, JSON_PRESERVE_ORDER | JSON_COMPACT);
    json_object_del(obj, "msg");

    if (!data) {
        return DSLINK_ALLOC_ERR;
    }
    int sentBytes = broker_ws_send(link, data, droppable);
    if ((sentBytes > 0) && throughput_output_needed()) {
        int sentMessages = broker_count_json_msg(obj);
        throughput_add_output(sentBytes, sentMessages);
    }
    dslink_free(data);
    return 0;
}

#ifdef BROKER_WS_SEND_THREAD_MODE
void broker_send_ws_thread(void *arg) {
    int ret;
    Broker *broker = (Broker *) arg;
    while (1) {
        uv_sem_wait(&broker->ws_send_sem);

        if (broker->closing_send_thread == 1) {
            log_debug("Closing ws send thread\n");
            break;
        }

        if(broker->currLink && (broker->currLink->pendingClose == 0)) {
            ret = wslay_event_send(broker->currLink->ws);
            if (ret != 0) {
                log_debug("Send error in thread: %d\n", ret);
            } else {
                log_debug("Message sent: %s\n", broker->currLink->name);
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
            if (wslay_event_want_write(broker->currLink->ws)) {
                uv_sem_post(&broker->ws_send_sem);
            } else {
                uv_sem_post(&broker->ws_queue_sem);
            }
#endif
        } else {
            uv_sem_post(&broker->ws_queue_sem);
        }

    }
}
#endif

int broker_ws_send(RemoteDSLink *link, const char *data, int droppable) {
    if (!link->ws || !link->client) {
        return -1;
    }

#ifdef BROKER_WS_SEND_THREAD_MODE
#ifdef BROKER_DROP_MESSAGE
    if(droppable) {
        if(uv_sem_trywait(&link->broker->ws_queue_sem)) {

            size_t tot_pending = 0;
            dslink_map_foreach(&link->broker->remote_connected) {
                RemoteDSLink* connLink = (RemoteDSLink*)entry->value->data;
                tot_pending += connLink->ws->queued_msg_length;
            }

            if(tot_pending > 200) {
                return -1;
            }
            else
                uv_sem_wait(&link->broker->ws_queue_sem);

        } else {

        }

    } else {
        uv_sem_wait(&link->broker->ws_queue_sem);
    }
#else
    (void)droppable;
    uv_sem_wait(&link->broker->ws_queue_sem);
#endif
#endif

    struct wslay_event_msg msg;
    msg.msg = (const uint8_t *) data;
    msg.msg_length = strlen(data);
    msg.opcode = WSLAY_TEXT_FRAME;

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
    uv_sem_post(&link->broker->ws_send_sem);
#endif
    log_debug("Message queued to be sent to %s: %s\n",link->name, data);
    return (int)msg.msg_length;
#else
    (void)droppable;
    if (link->client->poll) {
#ifdef BROKER_WS_DIRECT_SEND
        int ret = wslay_event_send(link->ws);
        if (ret != 0) {
            log_debug("Send error %d\n", ret);
        } else {
            log_debug("Message sent to %s: %s\n", (char *) link->dsId->data, data);
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


int broker_ws_generate_accept_key(const char *buf, size_t bufLen,
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
