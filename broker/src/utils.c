#include "broker/net/ws.h"
#include "broker/utils.h"

void broker_free_handle(uv_handle_t *handle) {
    dslink_free(handle);
}

void broker_utils_send_closed_resp(RemoteDSLink *link, json_t *req) {
    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);

    json_t *rid = json_object_get(req, "rid");
    json_object_set(resp, "rid", rid);
    json_object_set_new_nocheck(resp, "stream",
                                json_string_nocheck("closed"));

    broker_ws_send_obj(link, top);
    json_decref(top);
}
