#include <string.h>
#include <mbedtls/sha1.h>
#include <mbedtls/base64.h>

#define LOG_TAG "ws"
#include <dslink/log.h>
#include <dslink/err.h>

#include "broker/remote_dslink.h"
#include "broker/net/ws.h"

#define BROKER_WS_RESP "HTTP/1.1 101 Switching Protocols\r\n" \
                            "Upgrade: websocket\r\n" \
                            "Connection: Upgrade\r\n" \
                            "Sec-WebSocket-Accept: %s\r\n\r\n"

void broker_ws_send_init(Socket *sock, const char *accept) {
    char buf[1024];
    int bLen = snprintf(buf, sizeof(buf), BROKER_WS_RESP, accept);
    dslink_socket_write(sock, buf, (size_t) bLen);
}

int broker_ws_send_obj(RemoteDSLink *link, json_t *obj) {
    ++link->msgId;
    json_object_set_new_nocheck(obj, "msg", json_integer(link->msgId));
    char *data = json_dumps(obj, JSON_PRESERVE_ORDER | JSON_COMPACT);
    json_object_del(obj, "msg");

    if (!data) {
        return DSLINK_ALLOC_ERR;
    }
    broker_ws_send(link, data);
    dslink_free(data);
    return 0;
}

int broker_ws_send(RemoteDSLink *link, const char *data) {
    if (!link->ws) {
        return -1;
    }
    struct wslay_event_msg msg;
    msg.msg = (const uint8_t *) data;
    msg.msg_length = strlen(data);
    msg.opcode = WSLAY_TEXT_FRAME;
    wslay_event_queue_msg(link->ws, &msg);
    wslay_event_send(link->ws);
    log_debug("Message sent to %s: %s\n", (char *) link->dsId->data, data);
    return 0;
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
