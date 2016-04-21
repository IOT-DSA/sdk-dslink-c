#include <string.h>
#include <dslink/utils.h>

#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/stream.h"
#include "broker/msg/msg_list.h"


static
BrokerListStream *init_remote_list_stream(DownstreamNode *node, const char *path,
                                         RemoteDSLink *reqLink, uint32_t reqRid, uint32_t respRid) {
    BrokerListStream *stream = broker_stream_list_init(node);
    stream->remote_path = dslink_strdup(path);
    stream->responder_rid = respRid;

    dslink_map_set(&node->list_streams, dslink_str_ref(path),
                   dslink_ref(stream, NULL));
    broker_add_requester_list_stream(reqLink, stream, reqRid);
    return stream;
}

static
void send_list_request(BrokerListStream *stream,
                       DownstreamNode *node,
                       RemoteDSLink *reqLink,
                       const char *path,
                       uint32_t reqRid) {

    json_t *top = json_object();
    json_t *reqs = json_array();
    json_object_set_new_nocheck(top, "requests", reqs);

    json_t *req = json_object();
    json_array_append_new(reqs, req);
    json_object_set_new_nocheck(req, "method", json_string_nocheck("list"));
    json_object_set_new_nocheck(req, "path", json_string_nocheck(path));

    uint32_t rid = broker_node_incr_rid(node);

    json_object_set_new_nocheck(req, "rid",
                                json_integer(rid));

    broker_ws_send_obj(node->link, top);
    json_decref(top);

    if (stream == NULL) {
        stream = init_remote_list_stream(node, path, reqLink, reqRid, rid);
    } else {
        stream->responder_rid = rid;
    }

    // can be first time list
    // can also happen after link disconnect and reconnect
    dslink_map_set(&node->link->responder_streams, dslink_int_ref(rid),
                   dslink_ref(stream, NULL));
}


void broker_list_dslink(RemoteDSLink *reqLink,
                        DownstreamNode *node,
                        const char *path,
                        uint32_t reqRid) {
    ref_t *ref = dslink_map_get(&node->list_streams,
                                (char *) path);
    if (ref) {
        BrokerListStream *stream = ref->data;

        broker_add_requester_list_stream(reqLink, stream, reqRid);
        send_list_updates(reqLink, stream, reqRid);
        return;
    }
    if (node->link) {
        send_list_request(NULL, node, reqLink, path, reqRid);
    } else {
        // initialize a disconnected stream
        BrokerListStream *stream = init_remote_list_stream(node, path, reqLink, reqRid, 0);
        // reset cache to disconnected state
        broker_stream_list_reset_remote_cache(stream, NULL);
        send_list_updates(reqLink, stream, reqRid);
    }
}

static
void broker_list_dslink_send_cache(BrokerListStream *stream){
    json_t *cached_updates = broker_stream_list_get_cache(stream);

    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);

    json_object_set_new_nocheck(resp, "stream", json_string_nocheck("open"));
    json_object_set_new_nocheck(resp, "updates", cached_updates);

    dslink_map_foreach(&stream->requester_links) {
        json_object_del(resp, "rid");
        json_t *newRid = json_integer(*((uint32_t *) entry->value->data));
        json_object_set_new_nocheck(resp, "rid", newRid);

        RemoteDSLink *client = entry->key->data;
        broker_ws_send_obj(client, top);
    }

    json_decref(top);
}

void broker_list_dslink_response(RemoteDSLink *link, json_t *resp, BrokerListStream *stream) {
    json_t *updates = json_object_get(resp, "updates");
    if (json_is_array(updates)) {
        size_t i;
        json_t *child;
        uint8_t cache_need_reset = 1;
        json_array_foreach(updates, i, child) {
            // update cache
            if(json_is_array(child)) {
                json_t *childName = json_array_get(child, 0);
                json_t *childValue = json_array_get(child, 1);
                if (childName->type == JSON_STRING) {
                    const char *name = json_string_value(childName);
                    if (strcmp(name, "$base") == 0) {
                        // clear cache when $base or $is changed
                        if (cache_need_reset) {
                            broker_stream_list_reset_remote_cache(stream, link);
                            cache_need_reset = 0;
                        }
                        const char *originalBase = json_string_value(childValue);
                        if (originalBase) {
                            char buff[512];
                            strcpy(buff, stream->node->path);
                            strcat(buff, originalBase);
                            json_object_set_new_nocheck(
                                    stream->updates_cache, "$base",
                                    json_string_nocheck(buff));
                        }
                        continue; // already added to cache
                    }
                    if (strcmp(name, "$is") == 0) {
                        // clear cache when $base or $is changed
                        if (cache_need_reset) {
                            broker_stream_list_reset_remote_cache(stream, link);
                            cache_need_reset = 0;
                        }
                        if (strcmp(stream->remote_path, "/") == 0) {
                            const char *isValue = json_string_value(childValue);
                            if (strcmp(isValue, "dsa/broker") != 0) {
                                json_object_set_new_nocheck(stream->updates_cache,
                                                        name, json_string_nocheck("dsa/link"));
                                continue;
                            } else {
                                json_t * profile = json_object_get(stream->node->meta, "$is");
                                if (!profile || strcmp(json_string_value(profile), "dsa/broker") != 0) {
                                    json_object_set_new_nocheck(stream->node->meta, "$is", json_string_nocheck("dsa/broker"));

                                }
                            }
                        }
                    }
                    json_object_set_nocheck(stream->updates_cache,
                                            name, childValue);
                }
            } else if (json_is_object(child)) {
                json_t *childName = json_object_get(child, "name");
                json_t *change = json_object_get(child, "change");
                if (json_is_string(childName) && json_is_string(change)
                    && strcmp(json_string_value(change),"remove") == 0) {
                    json_object_del(stream->updates_cache,
                                    json_string_value(childName));
                } else {
                    // a list value update in a map? almost never used
                }
            }
        }
    }
    if (stream->cache_sent) {
        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_array_append(resps, resp);
        dslink_map_foreach(&stream->requester_links) {
            json_object_del(resp, "rid");
            json_t *newRid = json_integer(*((uint32_t *) entry->value->data));
            json_object_set_new_nocheck(resp, "rid", newRid);

            RemoteDSLink *client = entry->key->data;
            broker_ws_send_obj(client, top);
        }
        json_decref(top);
    } else {
        broker_list_dslink_send_cache(stream);
    }
}

void broker_stream_list_disconnect(BrokerListStream *stream) {
    // reset cache with disconnectedTs
    broker_stream_list_reset_remote_cache(stream, NULL);
    broker_list_dslink_send_cache(stream);
}

void broker_stream_list_connect(BrokerListStream *stream, DownstreamNode *node) {
    send_list_request(stream, node, NULL, stream->remote_path, 0);
}
