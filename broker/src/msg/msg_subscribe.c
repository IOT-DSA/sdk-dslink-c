#include <string.h>

#include <dslink/utils.h>
#include <dslink/col/list.h>

#include "broker/utils.h"
#include "broker/stream.h"
#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/msg/msg_subscribe.h"

static
void send_subscribe_request(DownstreamNode *node,
                            const char *path,
                            uint32_t sid,
                            uint8_t qos) {
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
    json_object_set_new_nocheck(p, "qos", json_integer(qos));

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

void broker_handle_local_subscribe(BrokerNode *node,
                                   RemoteDSLink *link,
                                   uint32_t sid) {
    ref_t *exist = dslink_map_get(&link->local_subs, &sid);
    if (exist) {
        Listener *existListener = exist->data;
        if (existListener->list == &node->on_value_update.list) {
            // if it's same as previous, reuse, and don't send new value
            return;
        }

        dslink_map_remove(&link->local_subs, &sid);

        listener_remove(existListener);

        dslink_free(existListener->data);
        dslink_free(existListener);
        dslink_decref(exist);
    }

    ref_t *key = dslink_int_ref(sid);
    void **data = malloc(sizeof(void *) * 2);
    data[0] = key->data;
    data[1] = link;

    Listener *l = listener_add(&node->on_value_update,
                               handle_data_val_update, data);
    handle_data_val_update(l, node);
    ref_t *value = dslink_ref(l, NULL);
    dslink_map_set(&link->local_subs, key, value);
}

void broker_subscribe_remote(DownstreamNode *respNode, RemoteDSLink *reqLink,
                             uint32_t sid, uint8_t qos, const char *path,
                             const char *respPath) {
    if (qos > 3) {
        qos = 3;
    }

    size_t vsize = strlen(path) + 2;
    char *vpath = dslink_malloc(vsize);
    snprintf(vpath, vsize, "%s%i", path, qos);

    ref_t *ref = dslink_map_get(&respNode->link->sub_paths, vpath);

    if (ref) {
        BrokerSubStream *bss = ref->data;

        ref_t *existingSub = dslink_map_remove_get(&bss->reqs, reqLink);
        if (existingSub) {
            SubRequester *existSubReq = existingSub->data;
            dslink_map_remove(&reqLink->req_sub_sids, existSubReq);
            broker_free_sub_requester(existSubReq);
            dslink_free(existingSub);
        }

        SubRequester *subReq = broker_create_sub_requester(reqLink, sid, qos, NULL);

        dslink_map_set(&bss->reqs, dslink_ref(reqLink, NULL), dslink_ref(subReq, NULL));
        dslink_map_set(&reqLink->req_sub_sids, dslink_int_ref(sid),
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

            broker_ws_send_obj(reqLink, top);
            json_decref(top);
        }
        dslink_free(vpath);
        return;
    }

    uint32_t respSid = broker_node_incr_sid(respNode);
    send_subscribe_request(respNode, respPath, respSid, qos);
    BrokerSubStream *bss = broker_stream_sub_init();
    bss->responder = respNode->link;
    bss->responder_sid = respSid;
    bss->virtual_path = dslink_str_ref(vpath);

    ref_t *bssRef = dslink_ref(bss, NULL);
    {
        SubRequester *subReq = broker_create_sub_requester(reqLink, sid, qos, NULL);
        dslink_map_set(&bss->reqs, dslink_ref(reqLink, NULL), dslink_ref(subReq, NULL));
        dslink_map_set(&reqLink->req_sub_sids, dslink_int_ref(sid), bssRef);
    }

    {
        ref = dslink_int_ref(respSid);
        dslink_map_set(&respNode->link->resp_sub_sids, ref,
                       dslink_incref(bssRef));

        ref = dslink_ref(dslink_strdup(vpath), dslink_free);
        bss->remote_path = dslink_incref(ref);
        dslink_map_set(&respNode->link->sub_paths, ref,
                       dslink_incref(bssRef));
    }
}

static
void add_pending_sub(List *subs, const char *path, uint32_t sid, uint8_t qos, RemoteDSLink *reqLink, List *qosQueue) {
    PendingSub *ps = dslink_malloc(sizeof(PendingSub));
    ps->path = dslink_strdup(path);
    ps->requester = reqLink;
    ps->reqSid = sid;
    ps->qos = qos;
    ps->req = reqLink->node;
    ps->qosQueue = qosQueue;
    ListNode *listNode = dslink_list_insert(subs, ps);
    ps->listNode = listNode;

    dslink_map_set(&reqLink->req_pending_sub_sids, dslink_int_ref(sid),
                   dslink_ref(ps, NULL));
}

void broker_free_pending_sub(PendingSub *sub, uint8_t freeNode) {
    if (freeNode) {
        list_remove_node(sub->listNode);
        dslink_free(sub->listNode);
    }
    dslink_map_remove(&sub->requester->req_pending_sub_sids, &sub->reqSid);
    dslink_free((char*)sub->path);
    dslink_free(sub);
}

static
void subs_list_free(void *p) {
    List *subs = p;
    dslink_list_foreach_nonext(subs) {
        ListNode *entry = (ListNode *) node;
        entry->list = NULL; //avoid list_remove_node
        PendingSub *sub = entry->value;
        broker_free_pending_sub(sub, 0);
        ListNodeBase *tmp = node->next;
        if ((intptr_t) node != (intptr_t) subs) {
            dslink_free(node);
        }
        node = tmp;
    }

    dslink_free(subs);
}

void broker_subscribe_disconnected_remote(RemoteDSLink *link,
                                          const char *path,
                                          uint32_t sid,
                                          uint8_t qos, List *qosQueue) {
    const char *name;
    if (path[1] == 'd') {
        name = path + sizeof("/downstream") + 1;
    } else {
        name = path + sizeof("/upstream") + 1;
    }
    
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

    add_pending_sub(subs, path, sid, qos, link, qosQueue);
}

void broker_subscribe_local_nonexistent(RemoteDSLink *link,
                                         const char *path,
                                         uint32_t sid, uint8_t qos) {
    ref_t *ref = dslink_map_get(&link->broker->local_pending_sub,
                                (char *) path);
    List *subs;
    if (ref) {
        subs = ref->data;
    } else {
        subs = dslink_calloc(1, sizeof(List));
        list_init(subs);
        dslink_map_set(&link->broker->local_pending_sub,
                       dslink_str_ref(path),
                       dslink_ref(subs, subs_list_free));
    }

    add_pending_sub(subs, path, sid, qos, link, NULL);
}

static
void handle_subscribe(RemoteDSLink *link, json_t *sub) {
    const char *path = json_string_value(json_object_get(sub, "path"));
    json_t *jSid = json_object_get(sub, "sid");
    if (!(path && jSid)) {
        return;
    }

    PermissionLevel permissionOnPath = get_permission(path, link->broker->root, link);
    if (permissionOnPath < PERMISSION_READ) {
        return;
    }

    char *out = NULL;
    DownstreamNode *node = (DownstreamNode *) broker_node_get(link->broker->root,
                                                              path, &out);
    uint32_t sid = (uint32_t) json_integer_value(jSid);

    json_t *jQos = json_object_get(sub, "qos");
    uint8_t qos = 0;

    if (json_is_integer(jQos)) {
        qos = (uint8_t) json_integer_value(jQos);
    }

    if (!node) {
        if (dslink_str_starts_with(path, "/downstream/") || dslink_str_starts_with(path, "/upstream/")) {
            broker_subscribe_disconnected_remote(link, path, sid, qos, NULL);
        } else {
            broker_subscribe_local_nonexistent(link, path, sid, qos);
        }
        return;
    }

    if (node->type == REGULAR_NODE) {
        broker_handle_local_subscribe((BrokerNode *) node, link, sid);
    } else {
        if (node->link) {
            broker_subscribe_remote(node, link, sid, qos, path, out);
        } else {
            broker_subscribe_disconnected_remote(link, path, sid, qos, NULL);
        }
    }
}

int broker_msg_handle_subscribe(RemoteDSLink *link, json_t *req) {
    broker_utils_send_closed_resp(link, req, NULL);

    json_t *paths = json_object_get(req, "paths");
    if (!json_is_array(paths)) {
        return 1;
    }

    json_t *maxPermitJson = json_object_get(req, "permit");
    PermissionLevel maxPermit = PERMISSION_CONFIG;
    if (json_is_string(maxPermitJson)) {
        maxPermit = permission_str_level(json_string_value(maxPermitJson));
    }

    if (maxPermit < PERMISSION_READ) {
        return 0;
    }

    size_t index;
    json_t *obj;
    json_array_foreach(paths, index, obj) {
        handle_subscribe(link, obj);
    }

    return 0;
}
