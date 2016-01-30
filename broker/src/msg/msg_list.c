#include <string.h>

#define LOG_TAG "msg_list"
#include <dslink/log.h>
#include <dslink/utils.h>

#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/stream.h"
#include "broker/msg/msg_list.h"

static
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
        BrokerNode *child = (BrokerNode *) entry->value;

        json_t *obj = json_object();
        if (!obj) {
            goto fail;
        }

        json_object_set_new(obj, "$is", json_string("node"));

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
    json_t *updates = json_array();


    if (dslink_map_contains(node->children, (void *) name)) {
        json_t *obj = json_object();

        {
            json_object_set_new(obj, "$is", json_string("node"));
            json_t *invokable = json_object_get(node->meta, "$invokable");
            if (invokable) {
                json_object_set_nocheck(obj, "$invokable", invokable);
            }
        }
        BrokerNode *child = dslink_map_get(node->children, (void *) name);
        if (child->type == DOWNSTREAM_NODE) {
            DownstreamNode *downstreamNode = (DownstreamNode *) child;
            if (downstreamNode->link && downstreamNode->link->linkData) {
                json_object_set(obj, "$linkData", downstreamNode->link->linkData);
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


    dslink_map_foreach(&stream->clients) {
        json_object_del(resp, "rid");
        json_t *newRid = json_integer(*((uint32_t *) entry->key));
        json_object_set_new_nocheck(resp, "rid", newRid);

        RemoteDSLink *client = entry->value;
        broker_ws_send_obj(client, top);
    }
    json_decref(top);
}

static
void broker_list_self(RemoteDSLink *reqLink,
                         BrokerNode *node, json_t *rid) {
    if (!node->list_stream) {
        node->list_stream = broker_stream_list_init();
        build_list_cache(node, node->list_stream);
    }

    uint32_t reqRid = (uint32_t) json_integer_value(rid);
    uint32_t *r = malloc(sizeof(uint32_t));
    *r = reqRid;
    void *tmp = reqLink;
    dslink_map_set(&node->list_stream->clients, r, &tmp);

    send_list_updates(reqLink, node->list_stream, reqRid);

    return;
}

static
void broker_list_dslink(RemoteDSLink *reqLink,
                        DownstreamNode *node,
                        const char *path,
                        uint32_t reqRid) {
    // TODO: so much error handling
    {
        BrokerListStream *stream = dslink_map_get(&node->link->list_streams,
                                                  (void *) path);
        if (stream) {
            uint32_t *r = malloc(sizeof(uint32_t));
            *r = reqRid;
            void *tmp = reqLink;
            dslink_map_set(&stream->clients, r, &tmp);
            send_list_updates(reqLink, stream, reqRid);
            return;
        }
    }

    uint32_t rid = 0;
    {
        json_t *top = json_object();
        json_t *reqs = json_array();
        json_object_set_new_nocheck(top, "requests", reqs);

        json_t *req = json_object();
        json_array_append_new(reqs, req);
        json_object_set_new_nocheck(req, "method", json_string("list"));
        json_object_set_new_nocheck(req, "path", json_string(path));

        rid = broker_node_incr_rid(node);
        json_object_set_new_nocheck(req, "rid",
                                    json_integer((json_int_t) rid));

        {
            broker_ws_send_obj(node->link, top);
            json_decref(top);
        }
    }
    {
        BrokerListStream *stream = broker_stream_list_init();
        stream->remotePath = dslink_strdup(path);

        void *tmp = reqLink;
        uint32_t *r = malloc(sizeof(uint32_t));
        *r = reqRid;
        dslink_map_set(&stream->clients, r, &tmp);

        r = malloc(sizeof(uint32_t));
        *r = rid;
        tmp = stream;
        dslink_map_set(&node->link->local_streams, r, &tmp);

        char *p = dslink_strdup(path);
        tmp = stream;
        dslink_map_set(&node->link->list_streams, p, &tmp);
    }
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
