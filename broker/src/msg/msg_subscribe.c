#include <string.h>

#include <dslink/utils.h>
#include <dslink/col/list.h>

#include "broker/utils.h"
#include "broker/stream.h"
#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/msg/msg_subscribe.h"

static
void subs_list_free(void *p) {
    List *subs = p;
    dslink_list_foreach_nonext(subs) {
        ListNode *entry = (ListNode *) node;

        PendingSub *sub = entry->value;
        dslink_free((char *) sub->path);
        dslink_free(sub);
        node = node->next;
        if ((intptr_t) node != (intptr_t) subs) {
            dslink_free(node);
        }
    }

    dslink_free(subs);
}

static
void send_subscribe_request(DownstreamNode *node,
                            const char *path,
                            uint32_t sid) {
    json_t *top = json_object();
    json_t *reqs = json_array();
    json_object_set_new_nocheck(top, "requests", reqs);

    json_t *req = json_object();
    json_array_append_new(reqs, req);

    uint32_t rid = broker_node_incr_rid(node);
    json_object_set_new_nocheck(req, "rid", json_integer(rid));
    json_object_set_new_nocheck(req, "method", json_string("subscribe"));
    json_t *paths = json_array();
    json_object_set_new_nocheck(req, "paths", paths);
    json_t *p = json_object();
    json_array_append_new(paths, p);
    json_object_set_new_nocheck(p, "path", json_string(path));
    json_object_set_new_nocheck(p, "sid", json_integer(sid));

    broker_ws_send_obj(node->link, top);
    json_decref(top);
}

static
int handle_data_val_update(Listener *listener, void *data) {
    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);

    json_t *resp = json_object();
    json_array_append_new(resps, resp);

    json_object_set_new_nocheck(resp, "rid", json_integer(0));

    json_t *updates = json_array();
    json_object_set_new_nocheck(resp, "updates", updates);

    void **arr = listener->data;
    uint32_t *sid = arr[0];
    RemoteDSLink *link = arr[1];
    {
        json_t *update = json_array();
        json_array_append_new(updates, update);

        json_array_append_new(update, json_integer(*sid));
        BrokerNode *node = data;
        if (node->value) {
            json_array_append(update, node->value);
        } else {
            json_array_append_new(update, NULL);
        }
        {
            char ts[32];
            dslink_create_ts(ts, sizeof(ts));
            json_t *jsonTs = json_string(ts);
            json_array_append_new(update, jsonTs);
        }
    }
    broker_ws_send_obj(link, top);
    json_decref(top);
    return 0;
}

static
void handle_local_subscribe(BrokerNode *node, RemoteDSLink *link, uint32_t sid) {
    ref_t *key = dslink_int_ref(sid);
    void **data = malloc(sizeof(void *) * 2);
    data[0] = key->data;
    data[1] = link;

    Listener *l = listener_add(&node->on_value_update,
                               handle_data_val_update, data);
    handle_data_val_update(l, node);
    ref_t *value = dslink_ref(l, NULL);
    dslink_map_set(&link->node->local_subs, key, value);
}

void broker_subscribe_remote(DownstreamNode *node, RemoteDSLink *link,
                             uint32_t sid, const char *path,
                             const char *respPath) {
    ref_t *ref = dslink_map_get(&node->sub_paths, (void *) path);
    if (ref) {
        BrokerSubStream *bss = ref->data;
        ref_t *s = dslink_int_ref(sid);
        dslink_map_set(&bss->clients, dslink_ref(link, NULL), s);
        dslink_map_set(&link->node->sub_sids, dslink_incref(s),
                       dslink_incref(ref));

        if (bss->last_value) {
            json_t *top = json_object();
            json_t *resps = json_array();
            json_object_set_new_nocheck(top, "responses", resps);
            json_t *newResp = json_object();
            json_array_append_new(resps, newResp);
            json_object_set_new_nocheck(newResp, "rid", json_integer(0));

            json_t *updates = json_array();
            json_object_set_new_nocheck(newResp, "updates", updates);
            json_array_append(updates, bss->last_value);

            if (json_is_array(bss->last_value)) {
                json_array_set_new(bss->last_value, 0, json_integer(sid));
            } else if (json_is_object(bss->last_value)) {
                json_object_set_new(bss->last_value, "sid", json_integer(sid));
            }

            broker_ws_send_obj(link, top);
            json_decref(top);
        }
        return;
    }

    uint32_t respSid = broker_node_incr_sid(node);
    send_subscribe_request(node, respPath, respSid);
    BrokerSubStream *bss = broker_stream_sub_init();
    bss->responder = node->link;
    bss->responder_sid = respSid;
    ref_t *bssRef = dslink_ref(bss, NULL);
    {
        ref = dslink_int_ref(sid);
        dslink_map_set(&bss->clients, dslink_ref(link, NULL), ref);
        dslink_map_set(&link->node->sub_sids, dslink_incref(ref), bssRef);
    }
    {
        ref = dslink_int_ref(respSid);
        dslink_map_set(&node->sub_sids, ref,
                       dslink_incref(bssRef));

        ref = dslink_ref(dslink_strdup(path), dslink_free);
        bss->remote_path = dslink_incref(ref);
        dslink_map_set(&node->sub_paths, ref,
                       dslink_incref(bssRef));
    }
}

void broker_subscribe_disconnected_remote(RemoteDSLink *link,
                                          const char *path,
                                          uint32_t sid) {
    const char *name = path + sizeof("/downstream");
    const char *end = strchr(name, '/');
    if (!end) {
        return;
    }

    const size_t len = end - name;
    ref_t *ref = dslink_map_getl(&link->broker->remote_pending_sub,
                                 (char *) name, len);
    List *subs;
    if (ref) {
        subs = ref->data;
    } else {
        subs = dslink_calloc(1, sizeof(List));
        list_init(subs);
        dslink_map_set(&link->broker->remote_pending_sub,
                       dslink_strl_ref(name, len),
                       dslink_ref(subs, subs_list_free));
    }

    PendingSub *ps = dslink_malloc(sizeof(PendingSub));
    ps->path = dslink_strdup(path);
    ps->reqSid = sid;
    ps->req = link->node;
    dslink_list_insert(subs, ps);
}

static
void handle_subscribe(RemoteDSLink *link, json_t *sub) {
    const char *path = json_string_value(json_object_get(sub, "path"));
    json_t *jSid = json_object_get(sub, "sid");
    if (!(path && jSid)) {
        return;
    }

    char *out = NULL;
    DownstreamNode *node = (DownstreamNode *) broker_node_get(link->broker->root,
                                                              path, &out);
    if (!node) {
        if (dslink_str_starts_with(path, "/downstream/")) {
            uint32_t s = (uint32_t) json_integer_value(jSid);
            broker_subscribe_disconnected_remote(link, path, s);
        } else {
            // TODO: add local pending sub to broker instance
        }
        return;
    }

    uint32_t sid = (uint32_t) json_integer_value(jSid);
    if (node->type == REGULAR_NODE) {
        handle_local_subscribe((BrokerNode *) node, link, sid);
    } else {
        broker_subscribe_remote(node, link, sid, path, out);
    }
}

int broker_msg_handle_subscribe(RemoteDSLink *link, json_t *req) {
    broker_utils_send_closed_resp(link, req, NULL);

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
