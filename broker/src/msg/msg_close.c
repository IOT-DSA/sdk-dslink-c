#include <jansson.h>
#include "broker/msg/msg_close.h"
#include "broker/net/ws.h"

void broker_send_close_request(RemoteDSLink *respLink,
                               uint32_t rid) {
    json_t *top = json_object();
    json_t *reqs = json_array();
    json_object_set_new_nocheck(top, "requests", reqs);

    json_t *req = json_object();
    json_array_append_new(reqs, req);
    json_object_set_new_nocheck(req, "method", json_string_nocheck("close"));
    json_object_set_new_nocheck(req, "rid", json_integer(rid));

    broker_ws_send_obj(respLink, top);
    json_decref(top);
}
