#include <string.h>
#include <dslink/utils.h>
#include <dslink/mem/mem.h>
#include <broker/msg/msg_close.h>

#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/msg/msg_list.h"

void send_list_updates(RemoteDSLink *reqLink,
                       BrokerListStream *stream,
                       uint32_t reqRid) {
    json_t *cached_updates = broker_stream_list_get_cache(stream);
    // TODO: send cached result only when list stream to the responder is running
    // otherwise it should wait for new list to finish to avoid sending outdated data
    if (!cached_updates) {
        return;
    }
    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);

    json_object_set_new_nocheck(resp, "rid", json_integer(reqRid));
    json_object_set_new_nocheck(resp, "stream", json_string("open"));
    json_object_set_new_nocheck(resp, "updates", cached_updates);

    broker_ws_send_obj(reqLink, top);
    json_decref(top);
}

int broker_list_req_closed(void *s, uint32_t reqRid) {
    BrokerListStream *stream = s;
    ref_t *ref = dslink_map_remove_get(&stream->requester_links, &reqRid);
    if (ref) {
        dslink_ref_decr(ref);
    }
    if (stream->requester_links.size == 0) {
        if (stream->node->type == DOWNSTREAM_NODE) {
            DownstreamNode *node = (DownstreamNode *)stream->node;
            if (node->link) {
                broker_send_close_request(node->link, stream->responder_rid);
                dslink_map_remove(&node->link->responder_streams, &stream->responder_rid);
            }
            dslink_map_remove(&node->list_streams, stream->remote_path);
        } else {
            BrokerNode *node = (BrokerNode *)stream->node;
            node->list_stream = NULL;
        }
    }
    return 0;
}

void broker_add_requester_list_stream(RemoteDSLink *reqLink, BrokerListStream *stream, uint32_t reqRid) {
    dslink_map_set(&stream->requester_links, dslink_int_ref(reqRid),
                   dslink_ref(reqLink, NULL));
    dslink_map_set(&reqLink->requester_streams, dslink_int_ref(reqRid),
                   dslink_ref(stream, NULL));
}



static
void build_list_cache(BrokerNode *node, BrokerListStream *stream) {

    json_t *profile = json_object_get(node->meta, "$is");
    if (profile) {
        json_object_set_nocheck(stream->updates_cache, "$is", profile);
    } else {
        json_object_set_new_nocheck(stream->updates_cache, "$is",
                                    json_string_nocheck("node"));
    }
    {
        const char *key;
        json_t *value;
        json_object_foreach(node->meta, key, value) {
            json_object_set_nocheck(stream->updates_cache, key, value);
        }
    }

    dslink_map_foreach(node->children) {
        BrokerNode *child = (BrokerNode *) entry->value->data;

        json_t *obj = json_object();
        if (!obj) {
            goto fail;
        }

        {
            json_object_set_new(obj, "$is", json_string("node"));
            json_t *handle = json_object_get(node->meta, "$invokable");
            if (handle) {
                json_object_set_nocheck(obj, "$invokable", handle);
            }
            handle = json_object_get(node->meta, "$type");
            if (handle) {
                json_object_set_nocheck(obj, "$type", handle);
            }
        }

        if (child->type == DOWNSTREAM_NODE) {
            DownstreamNode *downstreamNode = (DownstreamNode *)child;
            if (downstreamNode->link && downstreamNode->link->linkData) {
                json_object_set_nocheck(obj, "$linkData",
                                        downstreamNode->link->linkData);
            }
        }

        json_object_set_new_nocheck(stream->updates_cache, child->name, obj);
    }

fail:
    return;
}

void update_list_child(BrokerNode *node, BrokerListStream *stream, const char *name) {
    if (!(node && stream && name)) {
        return;
    }

    json_t *updates = json_array();


    if (dslink_map_contains(node->children, (void *) name)) {
        json_t *obj = json_object();
        {
            json_object_set_new(obj, "$is", json_string("node"));
            json_t *handle = json_object_get(node->meta, "$invokable");
            if (handle) {
                json_object_set_nocheck(obj, "$invokable", handle);
            }
            handle = json_object_get(node->meta, "$type");
            if (handle) {
                json_object_set_nocheck(obj, "$type", handle);
            }
        }
        ref_t *ref = dslink_map_get(node->children, (void *) name);
        if (ref) {
            BrokerNode *child = ref->data;
            if (child->type == DOWNSTREAM_NODE) {
                DownstreamNode *downstreamNode = (DownstreamNode *) child;
                if (downstreamNode->link && downstreamNode->link->linkData) {
                    json_object_set(obj, "$linkData", downstreamNode->link->linkData);
                }
            }
        }

        json_t *updateRow = json_array();

        json_array_append_new(updateRow, json_string(name));
        json_array_append_new(updateRow, obj);
        json_array_append_new(updates, updateRow);

        json_object_set_nocheck(stream->updates_cache, name, obj);

    } else {
        json_t *removeMap = json_object();
        json_object_set_new(removeMap, "name", json_string(name));
        json_object_set_new(removeMap, "change", json_string("remove"));
        json_array_append_new(updates, removeMap);
        json_object_del(stream->updates_cache, name);
    }


    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);

    json_object_set_new_nocheck(resp, "stream", json_string("open"));
    json_object_set_new_nocheck(resp, "updates", updates);


    dslink_map_foreach(&stream->requester_links) {
        json_object_del(resp, "rid");
        json_t *newRid = json_integer(*((uint32_t *) entry->key->data));
        json_object_set_new_nocheck(resp, "rid", newRid);

        RemoteDSLink *client = entry->value->data;
        broker_ws_send_obj(client, top);
    }
    json_decref(top);
}

static
void broker_list_self(RemoteDSLink *reqLink,
                         BrokerNode *node, json_t *rid) {
    if (!node->list_stream) {
        node->list_stream = broker_stream_list_init(node);
        build_list_cache(node, node->list_stream);
    }

    uint32_t reqRid = (uint32_t) json_integer_value(rid);
    uint32_t *r = dslink_malloc(sizeof(uint32_t));
    *r = reqRid;
    dslink_map_set(&node->list_stream->requester_links, dslink_ref(r, free),
                   dslink_ref(reqLink, NULL));

    send_list_updates(reqLink, node->list_stream, reqRid);

    return;
}


int broker_msg_handle_list(RemoteDSLink *link, json_t *req) {
    const char *path = json_string_value(json_object_get(req, "path"));
    json_t *rid = json_object_get(req, "rid");
    if (!(path && rid)) {
        return 1;
    }


    char *out = NULL;
    BrokerNode *node = broker_node_get(link->broker->root, path, &out);
    if (node) {
        if (node->type == REGULAR_NODE) {
            broker_list_self(link, node, rid);
        } else if (node->type == DOWNSTREAM_NODE) {
            uint32_t reqRid = (uint32_t) json_integer_value(rid);
            if (out == NULL) {
                out = "/";
            }
            broker_list_dslink(link, (DownstreamNode *) node, out, reqRid);
        }
    }

    return 0;
}
