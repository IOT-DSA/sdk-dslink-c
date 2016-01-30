#include <string.h>

#define LOG_TAG "msg_list_remote"
#include <dslink/log.h>
#include <dslink/utils.h>

#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/stream.h"
#include "broker/msg/msg_list.h"


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
                            strcpy(buff, ((BrokerListStream *) stream)->remotePath);
                            strcat(buff, "/");
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
                    // a list value update? almost never used
                }
            }
        }
    }
    if (stream->cache_sent) {
        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_array_append(resps, resp);
        dslink_map_foreach(&stream->clients) {
            json_object_del(resp, "rid");
            json_t *newRid = json_integer(*((uint32_t *) entry->key));
            json_object_set_new_nocheck(resp, "rid", newRid);

            RemoteDSLink *client = entry->value;
            broker_ws_send_obj(client, top);
        }
        json_decref(top);
    } else {
        json_t *cached_updates = broker_stream_list_get_cache(stream);

        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_t *resp = json_object();
        json_array_append_new(resps, resp);

        json_object_set_new_nocheck(resp, "stream", json_string("open"));
        json_object_set_new_nocheck(resp, "updates", cached_updates);

        dslink_map_foreach(&stream->clients) {
            json_object_del(resp, "rid");
            json_t *newRid = json_integer(*((uint32_t *) entry->key));
            json_object_set_new_nocheck(resp, "rid", newRid);

            RemoteDSLink *client = entry->value;
            broker_ws_send_obj(client, top);
        }

        json_decref(top);
    }
}