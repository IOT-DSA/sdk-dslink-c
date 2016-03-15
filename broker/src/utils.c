#include "broker/net/ws.h"
#include "broker/utils.h"

void broker_free_handle(uv_handle_t *handle) {
    dslink_free(handle);
}

void broker_utils_send_closed_resp(RemoteDSLink *link, json_t *req, const char* errorType) {
    if (!link || !req) {
        return;
    }
    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);

    json_t *rid = json_object_get(req, "rid");
    json_object_set(resp, "rid", rid);
    json_object_set_new_nocheck(resp, "stream",
                                json_string_nocheck("closed"));
    if (errorType) {
        json_t * errorObject = json_object();
        json_object_set_new(errorObject, "type", json_string_nocheck(errorType));
        json_object_set_new_nocheck(resp, "error", errorObject);
    }

    broker_ws_send_obj(link, top);
    json_decref(top);
}
