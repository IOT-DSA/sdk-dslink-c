#include <jansson.h>
#include <string.h>
#include <dslink/stream.h>
#include <dslink/utils.h>

#include "dslink/dslink.h"

#define LOG_TAG "response_handler"
#include "dslink/log.h"
#include "dslink/requester.h"
#include "dslink/ws.h"

int dslink_response_handle(DSLink *link, json_t *resp) {
    json_t *jsonRid = json_object_get(resp, "rid");
    uint32_t rid = (uint32_t) json_integer_value(jsonRid);

    if (rid == 0) {
        json_t *updates = json_object_get(resp, "updates");
        size_t index;
        json_t *entry;
        json_array_foreach(updates, index, entry) {
            uint32_t sid = (uint32_t) json_integer_value(json_array_get(entry, 0));
            json_t *val = json_array_get(entry, 1);
            json_t *ts = json_array_get(entry, 2);
            ref_t *cbref = dslink_map_get(link->requester->value_handlers, &sid);

            if (cbref) {
                SubscribeCallbackHolder *holder = cbref->data;
                value_sub_cb cb = holder->cb;
                if (cb) {
                    cb(link, val, ts);
                }
            }
        }
        return 0;
    }

    ref_t *holder_ref = dslink_map_get(link->requester->request_handlers, &rid);

    if (holder_ref && holder_ref->data) {
        RequestHolder *holder = holder_ref->data;
        request_handler_cb cb = holder->cb;
        request_handler_cb close_cb = holder->close_cb;

        json_t *status = json_object_get(resp, "stream");

        if (status && strcmp(json_string_value(status), "closed") == 0) {
            if (close_cb) {
                close_cb(link, resp);
            }
            dslink_map_remove(link->requester->request_handlers, &rid);
            dslink_decref(holder_ref);
        } else if (cb) {
            cb(link, resp);
        }
    }

    return 0;
}
