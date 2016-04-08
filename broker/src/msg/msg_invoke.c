#include <jansson.h>
#include <broker/utils.h>

#include "broker/broker.h"
#include "broker/net/ws.h"
#include "broker/msg/msg_invoke.h"
#include "broker/stream.h"
#include "broker/msg/msg_close.h"

static
void send_invoke_request(DownstreamNode *node,
                         json_t *req,
                         uint32_t rid,
                         const char *path,
                         PermissionLevel maxPermission) {
    json_t *top = json_object();
    json_t *reqs = json_array();
    json_object_set_new_nocheck(top, "requests", reqs);
    json_array_append(reqs, req);

    json_object_set_new_nocheck(req, "rid", json_integer(rid));
    json_object_set_new_nocheck(req, "path", json_string_nocheck(path));
    if (maxPermission < PERMISSION_CONFIG) {
        json_object_set_new_nocheck(req, "permit",
                                    json_string_nocheck(permission_level_str(maxPermission)));
    }

    broker_ws_send_obj(node->link, top);
    json_decref(top);
}

int remote_invoke_req_closed(void *s, RemoteDSLink *link) {
    (void) link;
    BrokerInvokeStream *stream = s;
    broker_send_close_request(stream->responder, stream->responder_rid);
    return 1;
}

int remote_invoke_resp_disconnected(void *s, RemoteDSLink *link) {
    (void) link;
    BrokerInvokeStream *stream = s;

    json_t *rid = json_integer(stream->requester_rid);
    broker_utils_send_closed_resp(stream->requester, rid, "disconnected");
    json_decref(rid);

    return 1;
}

int broker_msg_handle_invoke(RemoteDSLink *link, json_t *req) {
    json_t *reqRid = json_object_get(req, "rid");
    json_t *reqPath = json_object_get(req, "path");
    if (!(reqRid && reqPath)) {
        return 1;
    }
    json_t *maxPermitJson = json_object_get(req, "permit");
    PermissionLevel maxPermit = PERMISSION_CONFIG;
    if (json_is_string(maxPermitJson)) {
        maxPermit = permission_str_level(json_string_value(maxPermitJson));
    }

    const char *path = json_string_value(reqPath);
    char *out = NULL;
    BrokerNode *node = broker_node_get(link->broker->root, path, &out);
    if (!node) {
        broker_utils_send_closed_resp(link, req, "disconnected");
        return 0;
    }

    Broker *broker = mainLoop->data;

    PermissionLevel permissionOnPath = get_permission(path, broker->root, link);
    if (permissionOnPath > maxPermit) {
        permissionOnPath = maxPermit;
    }

    if (permissionOnPath == PERMISSION_NONE) {
        broker_utils_send_closed_resp(link, req, "permissionDenied");
        return 0;
    }
    if (node->type == REGULAR_NODE) {
        json_t *invokableJson = json_object_get(node->meta, "$invokable");

        PermissionLevel level = permission_str_level(json_string_value(invokableJson));
        if (level > permissionOnPath) {
            broker_utils_send_closed_resp(link, req, "permissionDenied");
        } else if (node->on_invoke) {
            node->on_invoke(link, node, req, maxPermit);
        }
        return 0;
    } else if (node->type != DOWNSTREAM_NODE) {
        // Unknown node type
        broker_utils_send_closed_resp(link, req, "disconnected");
        return 0;
    }

    DownstreamNode *ds = (DownstreamNode *) node;
    uint32_t rid = broker_node_incr_rid(ds);

    if (!ds->link) {
        broker_utils_send_closed_resp(link, req, "disconnected");
        return 0;
    }

    BrokerInvokeStream *s = broker_stream_invoke_init();

    s->responder_rid = rid;
    s->responder = ds->link;
    s->resp_close_cb = remote_invoke_resp_disconnected;

    s->requester_rid = (uint32_t) json_integer_value(reqRid);
    s->requester = link;
    s->req_close_cb = remote_invoke_req_closed;

    ref_t *refStream = dslink_ref(s, NULL);
    dslink_map_set(&ds->link->responder_streams, dslink_int_ref(rid),
                   refStream);

    ref_t *findref = dslink_map_remove_get(&link->requester_streams, &s->requester_rid);
    if (findref) {
        BrokerStream *oldstream = findref->data;
        if (oldstream->req_close_cb) {
            oldstream->req_close_cb(oldstream, link);
        }
        broker_stream_free(oldstream);
        dslink_decref(findref);
    }
    dslink_map_set(&link->requester_streams,
                   dslink_int_ref(s->requester_rid),
                   dslink_incref(refStream));

    send_invoke_request(ds, req, rid, out, permissionOnPath);
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
    if (broker_invoke_safe_json_set(param, "name", json_string_nocheck(name)) != 0
        || broker_invoke_safe_json_set(param, "type", json_string_nocheck(type)) != 0
        || json_array_append_new(params, param) != 0) {
        json_decref(param);
        return 1;
    }
    return 0;
}
