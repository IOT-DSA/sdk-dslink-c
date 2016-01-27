#define LOG_TAG "msg_handler"
#include <dslink/log.h>

#include <string.h>
#include <dslink/ws.h>
#include "broker/msg/msg_handler.h"
#include <broker/msg/msg_list.h>

static
void broker_handle_req(Broker *broker, json_t *req) {
    const char *method = json_string_value(json_object_get(req, "method"));
    if (!method) {
        return;
    }
    if (strcmp(method, "list") == 0) {
        if (broker_msg_handle_list(broker, req) != 0) {
            log_err("Failed to handle list request\n");
        }
    } else {
        log_err("Method unspecified: %s\n", method);
    }
}

void broker_msg_handle(Broker *broker,
                       json_t *data) {
    if (!data) {
        return;
    }
    json_incref(data);
    json_t *reqs = json_object_get(data, "requests");
    if (broker->link->isRequester && reqs) {
        json_t *req;
        size_t index = 0;
        json_array_foreach(reqs, index, req) {
            broker_handle_req(broker, req);
        }
    }

    json_t *resps = json_object_get(data, "responses");
    if (broker->link->isResponder && resps) {
        // TODO
    }

    json_decref(data);
}
