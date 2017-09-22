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

int broker_ws_send_obj(RemoteDSLink *link, json_t *obj) {
    ++link->msgId;
    json_object_set_new_nocheck(obj, "msg", json_integer(link->msgId));

    // DECODE OBJ
    char* data = NULL;
    int len;
    int opcode;

    log_debug("Message(as %s) is trying sent to %s: %s\n",
                  (link->is_msgpack==1)?"msgpack":"json",
                  (char *) link->dsId->data,
                  json_dumps(obj,JSON_INDENT(0)));

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
        log_err("Message(as %s) is failed sent to %s: %s\n",
                  (link->is_msgpack==1)?"msgpack":"json",
                  (char *) link->dsId->data,
                  json_dumps(obj,JSON_INDENT(0)));
    }

    if (throughput_output_needed()) {
        int sentMessages = broker_count_json_msg(obj);
        throughput_add_output(sentBytes, sentMessages);
    }
    dslink_free(data);
    return 0;
}

int broker_ws_send_ping(RemoteDSLink *link) {
    json_t *obj = json_object();

    // DECODE OBJ
    char* data = NULL;
    int len;
    int opcode;

    log_debug("Message (Ping)(as %s) is trying sent to %s\n",
              (link->is_msgpack==1)?"msgpack":"json",
              (char *) link->dsId->data);

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

    if (!data) {
        return DSLINK_ALLOC_ERR;
    }

    int sentBytes = broker_ws_send(link, data, len, opcode);

    if(sentBytes == -1)
    {
        log_err("Message (Ping)(as %s) is failed sent to %s\n",
                (link->is_msgpack==1)?"msgpack":"json",
                (char *) link->dsId->data);
    }

    if (throughput_output_needed()) {
        int sentMessages = broker_count_json_msg(obj);
        throughput_add_output(sentBytes, sentMessages);
    }


    json_delete(obj);

    dslink_free(data);
    return 0;
}

int broker_ws_send(RemoteDSLink *link, const char *data, int len, int opcode) {
    if (!link->ws || !link->client) {
        return -1;
    }
    struct wslay_event_msg msg;
    msg.msg = (const uint8_t *) data;
    msg.msg_length = len;
    msg.opcode = opcode;
    wslay_event_queue_msg(link->ws, &msg);

    if(link->client->poll) {
        uv_poll_start(link->client->poll, UV_READABLE | UV_WRITABLE, link->client->poll_cb);

        log_debug("Message(%s) sent to %s: %s\n",
                  (opcode==WSLAY_TEXT_FRAME)?"text":"binary",
                  (char *) link->dsId->data, data);

        return (int)msg.msg_length;
    }

    return -1;
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
