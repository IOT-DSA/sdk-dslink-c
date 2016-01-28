#define LOG_TAG "ws"
#include <dslink/log.h>
#include <dslink/err.h>
#include <string.h>

#include "broker/remote_dslink.h"
#include "broker/net/ws.h"

int broker_ws_send_obj(RemoteDSLink *link, json_t *obj) {
    char *data = json_dumps(obj, JSON_PRESERVE_ORDER);
    if (!data) {
        return DSLINK_ALLOC_ERR;
    }
    broker_ws_send(link, data);
    free(data);
    return 0;
}

int broker_ws_send(RemoteDSLink *link, const char *data) {
    struct wslay_event_msg msg;
    msg.msg = (const uint8_t *) data;
    msg.msg_length = strlen(data);
    msg.opcode = WSLAY_TEXT_FRAME;
    wslay_event_queue_msg(link->ws, &msg);
    wslay_event_send(link->ws);
    log_debug("Message sent to %s: %s\n", link->dsId, data);
    return 0;
}
