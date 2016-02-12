#include <dslink/utils.h>
#include <dslink/mem/mem.h>
#include "broker/stream.h"
#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/data/data.h"
#include "broker/msg/msg_subscribe.h"

static
void handle_subscribe(RemoteDSLink *link, json_t *sub) {
    const char *path = json_string_value(json_object_get(sub, "path"));
    uint32_t sid = (uint32_t) json_integer_value(json_object_get(sub, "sid"));
    if (!(path && sid)) {
        return;
    }

    char *out = NULL;
    DownstreamNode *node = (DownstreamNode *) broker_node_get(link->broker->root,
                                                              path, &out);
    if (!node || node->type != DOWNSTREAM_NODE) {
        return;
    }

    {
        ref_t *ref = dslink_map_get(&node->link->sub_paths, (void *) path);
        if (ref) {
            BrokerSubStream *bss = ref->data;
            uint32_t *s = dslink_malloc(sizeof(uint32_t));
            *s = sid;
            dslink_map_set(&bss->clients, dslink_ref(s, dslink_free),
                           dslink_ref(link, NULL));

            if (bss->last_value) {
                json_t *top = json_object();
                json_t *resps = json_array();
                json_object_set_new_nocheck(top, "responses", resps);
                json_t *newResp = json_object();
                json_array_append_new(resps, newResp);
                json_object_set_new_nocheck(newResp, "rid", json_integer(0));

                json_t *updates = json_array();
                json_object_set_new_nocheck(newResp, "updates", updates);

                json_t *update = json_array();
                json_array_set_new(update, 0, json_integer(sid));
                json_array_append(update, bss->last_value);
                json_array_append_new(updates, update);

                broker_ws_send_obj(link, top);
                json_decref(top);
            }
            return;
        }
    }

    uint32_t respSid = broker_node_incr_sid(node);
    {
        json_t *top = json_object();
        json_t *reqs = json_array();
        json_object_set_nocheck(top, "requests", reqs);

        json_t *req = json_object();
        json_array_append_new(reqs, req);

        uint32_t rid = broker_node_incr_rid(node);
        json_object_set_new_nocheck(req, "rid", json_integer(rid));
        json_object_set_new_nocheck(req, "method", json_string("subscribe"));
        json_t *paths = json_array();
        json_object_set_new_nocheck(req, "paths", paths);
        json_t *p = json_object();
        json_array_append_new(paths, p);
        json_object_set_new_nocheck(p, "path", json_string(out));
        json_object_set_new_nocheck(p, "sid", json_integer(respSid));

        broker_ws_send_obj(node->link, top);
        json_decref(top);
    }
    BrokerSubStream *bss = broker_stream_sub_init();
    {
        uint32_t *s = dslink_malloc(sizeof(uint32_t));
        *s = sid;
        dslink_map_set(&bss->clients, dslink_ref(s, free),
                       dslink_ref(link, NULL));
    }
    {
        uint32_t *s = dslink_malloc(sizeof(uint32_t));
        *s = respSid;
        dslink_map_set(&node->link->sub_sids, dslink_ref(s, free),
                       dslink_ref(bss, NULL));
    }
    {
        char *p = dslink_strdup(path);
        dslink_map_set(&node->link->sub_paths, dslink_ref(p, free),
                       dslink_ref(bss, NULL));
    }
}

int broker_msg_handle_subscribe(RemoteDSLink *link, json_t *req) {
    broker_data_send_closed_resp(link, req);

    json_t *paths = json_object_get(req, "paths");
    if (!json_is_array(paths)) {
        return 1;
    }

    size_t index;
    json_t *obj;
    json_array_foreach(paths, index, obj) {
        handle_subscribe(link, obj);
    }

    return 0;
}
