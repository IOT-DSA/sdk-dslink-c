#include <jansson.h>

#include "broker/broker.h"
#include "broker/net/ws.h"
#include "broker/msg/msg_invoke.h"
#include "broker/stream.h"
#include "broker/msg/msg_close.h"

int remote_invoke_req_closed(void *s, uint32_t reqId) {
    (void) reqId;
    BrokerInvokeStream *stream = s;
    broker_send_close_request(stream->responder, stream->responder_rid);
    dslink_map_remove(&stream->responder->responder_streams, &stream->responder_rid);
    return 0;
}

int remote_invoke_resp_disconnected(void *s, uint32_t respRid) {
    (void) s;
    (void) respRid;
    // TODO, send a disconnect error to requester, and remove it from request map
    return 0;
}

int broker_msg_handle_invoke(RemoteDSLink *link, json_t *req) {
    json_t *jRid = json_object_get(req, "rid");
    json_t *jPath = json_object_get(req, "path");
    if (!(jRid && jPath)) {
        return 1;
    }

    const char *path = json_string_value(jPath);
    char *out = NULL;
    BrokerNode *node = broker_node_get(link->broker->root, path, &out);
    if (!node) {
        return 1;
    }

    if (node->type == REGULAR_NODE) {
        if (node->on_invoke) {
            node->on_invoke(link, node, req);
        }
        return 0;
    } else if (node->type != DOWNSTREAM_NODE) {
        // Unknown node type
        return 1;
    }

    json_t *top = json_object();
    json_t *reqs = json_array();
    json_object_set_new_nocheck(top, "requests", reqs);
    json_array_append(reqs, req);

    DownstreamNode *ds = (DownstreamNode *) node;
    uint32_t rid = broker_node_incr_rid(ds);
    {
        BrokerInvokeStream *s = broker_stream_invoke_init();

        s->responder_rid = rid;
        s->responder = ds->link;
        dslink_map_set(&ds->link->responder_streams, dslink_int_ref(rid),
                       dslink_ref(s, NULL));
        s->resp_close_cb = remote_invoke_resp_disconnected;

        s->requester_rid = (uint32_t) json_integer_value(jRid);
        s->requester = link;
        dslink_map_set(&ds->link->requester_streams, dslink_int_ref(s->requester_rid),
                       dslink_ref(s, NULL));
        s->req_close_cb = remote_invoke_req_closed;
    }

    json_t *newRid = json_integer(rid);
    json_object_set_new_nocheck(req, "rid", newRid);
    json_object_set_new_nocheck(req, "path", json_string(out));

    broker_ws_send_obj(ds->link, top);
    json_decref(top);
    return 0;
}

static
int broker_invoke_safe_json_set(json_t *obj, const char *name, json_t *data) {
    if (json_object_set_new(obj, name, data) != 0) {
        json_decref(data);
        return 1;
    }
    return 0;
}

int broker_invoke_create_param(json_t *params,
                               const char *name, const char *type) {
    json_t *param = json_object();
    if (broker_invoke_safe_json_set(param, "name", json_string(name)) != 0
        || broker_invoke_safe_json_set(param, "type", json_string(type)) != 0
        || json_array_append_new(params, param) != 0) {
        json_decref(param);
        return 1;
    }
    return 0;
}
