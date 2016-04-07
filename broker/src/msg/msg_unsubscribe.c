#include <broker/subscription.h>
#include "broker/net/ws.h"
#include "broker/node.h"
#include "broker/utils.h"
#include "broker/stream.h"
#include "broker/msg/msg_unsubscribe.h"

void broker_msg_send_unsubscribe(BrokerSubStream *bss, RemoteDSLink *link) {
    if (!((DownstreamNode*)bss->respNode)->link) {
        return;
    }
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
        json_array_append_new(sids, json_integer(bss->respSid));
        json_object_set_new_nocheck(req, "sids", sids);
    }

    broker_ws_send_obj(((DownstreamNode*)bss->respNode)->link, top);
    json_decref(top);
}

static
void handle_unsubscribe(RemoteDSLink *link, uint32_t sid) {
    ref_t *ref = dslink_map_remove_get(&link->node->req_sub_sids, &sid);
    if (ref) {
        SubRequester *subreq = ref->data;
        broker_free_sub_requester(subreq);
        dslink_decref(ref);
    }
}

int broker_msg_handle_unsubscribe(RemoteDSLink *link, json_t *req) {
    broker_utils_send_closed_resp(link, req, NULL);

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
