#include <dslink/utils.h>
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

    {
        BrokerSubStream *bss = dslink_map_get(&link->sub_paths, (void *) path);
        if (bss) {
            uint32_t *s = malloc(sizeof(uint32_t));
            *s = sid;
            void *tmp = link;
            dslink_map_set(&bss->clients, s, &tmp);

            if (bss->last_value) {
                json_t *top = json_object();
                json_t *resps = json_array();
                json_object_set_new_nocheck(top, "responses", resps);
                json_t *newResp = json_object();
                json_array_append_new(resps, newResp);
                json_object_set_new_nocheck(newResp, "rid", json_integer(0));

                json_t *updates = json_array();
                json_object_set_new_nocheck(newResp, "updates", updates);

                json_t *update = bss->last_value;
                json_array_set_new(update, 0, json_integer(sid));
                json_array_append(updates, update);

                broker_ws_send_obj(link, top);
                json_decref(top);
            }
            return;
        }
    }

    char *out = NULL;
    BrokerNode *node = broker_node_get(link->broker->root, path, &out);
    if (!node || node->type != DOWNSTREAM_NODE) {
        return;
    }

    DownstreamNode *dn = (DownstreamNode *) node;
    uint32_t respSid = broker_node_incr_sid(dn);
    {
        json_t *top = json_object();
        json_t *reqs = json_array();
        json_object_set_nocheck(top, "requests", reqs);

        json_t *req = json_object();
        json_array_append_new(reqs, req);

        uint32_t rid = broker_node_incr_rid(dn);
        json_object_set_new_nocheck(req, "rid", json_integer(rid));
        json_object_set_new_nocheck(req, "method", json_string("subscribe"));
        json_t *paths = json_array();
        json_object_set_new_nocheck(req, "paths", paths);
        json_t *p = json_object();
        json_array_append_new(paths, p);
        json_object_set_new_nocheck(p, "path", json_string(out));
        json_object_set_new_nocheck(p, "sid", json_integer(respSid));

        broker_ws_send_obj(((DownstreamNode *) node)->link, top);
        json_decref(top);
    }
    BrokerSubStream *bss = broker_stream_sub_init();
    {
        uint32_t *s = malloc(sizeof(uint32_t));
        *s = sid;
        void *tmp = link;
        dslink_map_set(&bss->clients, s, &tmp);
    }
    {
        uint32_t *s = malloc(sizeof(uint32_t));
        *s = respSid;
        void *tmp = bss;
        dslink_map_set(&dn->link->sub_sids, s, &tmp);
    }
    {
        char *p = dslink_strdup(path);
        void *tmp = bss;
        dslink_map_set(&dn->link->sub_paths, p, &tmp);
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
