#include "broker/net/ws.h"
#include "broker/node.h"
#include "broker/utils.h"
#include "broker/stream.h"
#include "broker/msg/msg_unsubscribe.h"

void broker_msg_send_unsubscribe(BrokerSubStream *bss, RemoteDSLink *link) {
    json_t *top = json_object();
    json_t *reqs = json_array();
    json_object_set_new_nocheck(top, "requests", reqs);

    json_t *req = json_object();
    json_array_append_new(reqs, req);
    json_object_set_new_nocheck(req, "method",
                                json_string_nocheck("unsubscribe"));

    uint32_t rid = broker_node_incr_rid(link->node);
    json_object_set_new_nocheck(req, "rid",
                                json_integer(rid));

    {
        json_t *sids = json_array();
        json_array_append_new(sids, json_integer(bss->responder_sid));
        json_object_set_new_nocheck(req, "sids", sids);
    }

    broker_ws_send_obj(bss->responder, top);
    json_decref(top);
}

static
void handle_unsubscribe(RemoteDSLink *link, uint32_t sid) {
    ref_t *ref = dslink_map_remove_get(&link->node->local_subs, &sid);
    if (ref) {
        Listener *listener = ref->data;
        listener_remove(listener);

        dslink_free(listener->data);
        dslink_free(listener);
        dslink_decref(ref);
        return;
    }

    ref = dslink_map_remove_get(&link->node->sub_sids, &sid);
    if (!ref) {
        return;
    }

    BrokerSubStream *bss = ref->data;
    broker_stream_free((BrokerStream *) bss, link);
    dslink_decref(ref);
}

int broker_msg_handle_unsubscribe(RemoteDSLink *link, json_t *req) {
    broker_utils_send_closed_resp(link, req);

    json_t *sids = json_object_get(req, "sids");
    if (sids) {
        size_t index;
        json_t *value;
        json_array_foreach(sids, index, value) {
            uint32_t sid = (uint32_t) json_integer_value(value);
            handle_unsubscribe(link, sid);
        }
    }

    return 0;
}
