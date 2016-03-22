#include <jansson.h>
#include <string.h>
#include <dslink/stream.h>
#include <dslink/utils.h>

#include "dslink/dslink.h"

#define LOG_TAG "response_handler"
#include "dslink/log.h"
#include "dslink/requester.h"

int dslink_response_handle(DSLink *link, json_t *resp) {
    json_t *jsonRid = json_object_get(resp, "rid");
    uint32_t rid = (uint32_t) json_integer_value(jsonRid);

    ref_t *holder_ref = dslink_map_get(link->requester->request_handlers, &rid);

    if (holder_ref && holder_ref->data) {
        RequestHolder *holder = holder_ref->data;
        request_handler_cb cb = holder->cb;

        if (cb) {
            cb(link, resp);
        }
    }

    return 0;
}
