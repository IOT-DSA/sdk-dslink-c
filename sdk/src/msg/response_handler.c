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
