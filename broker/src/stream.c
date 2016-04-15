#include <stdlib.h>
#include <string.h>
#include <dslink/utils.h>
#include <dslink/mem/mem.h>
#include <broker/msg/msg_subscribe.h>
#include "broker/msg/msg_unsubscribe.h"
#include "broker/msg/msg_list.h"
#include <broker/subscription.h>

static
int broker_map_dslink_cmp(void *key, void *other, size_t len) {
    (void) len;
    RemoteDSLink *a = key;
    RemoteDSLink *b = other;
    return strcmp(a->dsId->data, b->dsId->data);
}

static
size_t broker_map_dslink_len(void *key) {
    RemoteDSLink *a = key;

    if (!a->dsId) {
        return 0;
    }

    return strlen(a->dsId->data);
}

static
uint32_t broker_map_dslink_hash(void *key, size_t len) {
    key = ((RemoteDSLink *) key)->dsId->data;
    return dslink_map_hash_key(key, len);
}


static
int broker_map_node_cmp(void *key, void *other, size_t len) {
    (void) len;
    BrokerNode *a = key;
    BrokerNode *b = other;
    return strcmp(a->path, b->path);
}

static
size_t broker_map_node_len(void *key) {
    BrokerNode *a = key;

    if (!a->path) {
        return 0;
    }

    return strlen(a->path);
}

static
uint32_t broker_map_node_hash(void *key, size_t len) {
    key = (void*)((BrokerNode *) key)->path;
    return dslink_map_hash_key(key, len);
}


BrokerListStream *broker_stream_list_init(void *node) {
    BrokerListStream *stream = dslink_calloc(1, sizeof(BrokerListStream));
    if (!stream) {
        return NULL;
    }
    stream->type = LIST_STREAM;
    stream->req_close_cb = broker_list_req_closed;
    if (dslink_map_init(&stream->requester_links, broker_map_dslink_cmp,
                        broker_map_dslink_len, broker_map_dslink_hash) != 0) {
        dslink_free(stream);
        return NULL;
    }

    stream->updates_cache = json_object();
    stream->node = node;
    if (!stream->updates_cache) {
        dslink_free(stream);
        return NULL;
    }

    return stream;
}

BrokerSubStream *broker_stream_sub_init() {
    BrokerSubStream *stream = dslink_calloc(1, sizeof(BrokerSubStream));
    if (!stream) {
        return NULL;
    }

    stream->type = SUBSCRIPTION_STREAM;

    if (dslink_map_init(&stream->reqSubs, broker_map_node_cmp,
                        broker_map_node_len, broker_map_node_hash) != 0) {
        dslink_free(stream);
        return NULL;
    }

    return stream;
}

BrokerInvokeStream *broker_stream_invoke_init() {
    BrokerInvokeStream *stream = dslink_calloc(1, sizeof(BrokerInvokeStream));
    if (!stream) {
        return NULL;
    }

    stream->type = INVOCATION_STREAM;
    return stream;
}

void broker_stream_free(BrokerStream *stream) {
    if (!stream) {
        return;
    }

    if (stream->type == LIST_STREAM) {
        BrokerListStream *s = (BrokerListStream *) stream;
        dslink_map_foreach(&s->requester_links) {
            RemoteDSLink *link = entry->key->data;
            uint32_t *rid = entry->value->data;
            dslink_map_remove(&link->requester_streams, rid);
        }
        if (s->node->type == DOWNSTREAM_NODE) {
            DownstreamNode *dnode = (DownstreamNode *)s->node;
            if (dnode->link) {
                dslink_map_remove(&dnode->link->responder_streams, &s->responder_rid);
            }
        }
        dslink_map_free(&s->requester_links);
        dslink_free(s->remote_path);
        json_decref(s->updates_cache);
        dslink_free(stream);
    } else if (stream->type == INVOCATION_STREAM) {
        BrokerInvokeStream *bis = (BrokerInvokeStream *) stream;
        if (bis->requester) {
            dslink_map_remove(&bis->requester->requester_streams, &bis->requester_rid);
        }
        if (bis->responder) {
            dslink_map_remove(&bis->responder->responder_streams, &bis->responder_rid);
        }
        dslink_free(stream);
    } else if (stream->type == SUBSCRIPTION_STREAM) {
        BrokerSubStream *bss = (BrokerSubStream *) stream;
        if (bss->respNode->type == DOWNSTREAM_NODE) {
            dslink_map_foreach(&bss->reqSubs) {
                SubRequester *reqsub = entry->value->data;
                reqsub->stream = NULL;
                reqsub->respNode = NULL;
                broker_subscribe_disconnected_remote(reqsub->path, reqsub);
            }
            DownstreamNode* dnode = (DownstreamNode*)bss->respNode;
            broker_msg_send_unsubscribe(bss, ((DownstreamNode*)bss->respNode)->link);

            dslink_map_remove(&dnode->resp_sub_streams, bss->remote_path);
            dslink_map_remove(&dnode->resp_sub_sids, &bss->respSid);
        } else {
            dslink_map_foreach(&bss->reqSubs) {
                SubRequester *reqsub = entry->value->data;
                reqsub->stream = NULL;
                reqsub->respNode = NULL;
                broker_subscribe_local_nonexistent(reqsub->path, reqsub);
            }
            bss->respNode->sub_stream = NULL;
        }
        dslink_map_free(&bss->reqSubs);
        dslink_free(bss->remote_path);
        json_decref(bss->last_value);
        dslink_free(stream);
    }

}



void requester_stream_closed(BrokerStream *stream, RemoteDSLink *link) {
    if (stream->req_close_cb) {
        stream->req_close_cb(stream, link);
    }
    if (stream->type == LIST_STREAM) {
        BrokerListStream *s = (BrokerListStream *) stream;
        if (s->node && s->requester_links.size > 0) {
            // don't free list stream when it's still open
            return;
        }
    }
    broker_stream_free(stream);
}

void responder_stream_closed(BrokerStream *stream, RemoteDSLink *link) {
    if (stream->resp_close_cb) {
        if (stream->resp_close_cb(stream, link)) {
            broker_stream_free(stream);
        }
    }
}

static inline
void add_to_update(json_t *updates, const char *key, json_t *value) {
    json_t *update = json_array();

    // name
    json_array_append_new(update, json_string_nocheck(key));
    //value
    json_array_append(update, value);

    json_array_append_new(updates, update);
}

json_t *broker_stream_list_get_cache(BrokerListStream *stream) {
    size_t cacheSize = json_object_size(stream->updates_cache);
    if (cacheSize == 0) {
        return NULL;
    }

    json_t *updates = json_array();
    const char *key;
    json_t *value;


    json_t *valueBase = json_object_get(stream->updates_cache, "$base");
    if (valueBase != NULL) {
        add_to_update(updates, "$base", valueBase);
    }

    json_t *valueIs = json_object_get(stream->updates_cache, "$is");
    if (valueIs != NULL) {
        add_to_update(updates, "$is", valueIs);
    }

    json_object_foreach(stream->updates_cache, key, value) {
        if (value != valueIs && value != valueBase) {
            // $base and $is should be added before everything
            add_to_update(updates, key, value);
        }
    }
    return updates;
}

void broker_stream_list_reset_remote_cache(BrokerListStream *stream,
                                           RemoteDSLink *link) {
    json_object_clear(stream->updates_cache);
    if (link) {
        if (strcmp(stream->remote_path,"/") != 0) {
            json_object_set_new_nocheck(stream->updates_cache, "$base", json_string_nocheck(link->path));
        }

        if (strcmp(stream->remote_path, "/") == 0) {
            // add linkData into the updates_cache
            if (link->linkData) {
                json_object_set_nocheck(stream->updates_cache, "$linkData", link->linkData);
            }
            const char *key;
            json_t *value;
            json_object_foreach(stream->node->meta, key, value) {
                if (*key == '@') {
                    json_object_set_nocheck(stream->updates_cache, key, value);
                }
            }
        } else {
            // set downstream virtual attribute
            json_t *meta = set_downstream_attribute(stream->remote_path+1, (DownstreamNode*)stream->node, NULL, NULL);
            if (meta) {
                const char *key;
                json_t *value;
                json_object_foreach(meta, key, value) {
                    if (*key == '@') {
                        json_object_set_nocheck(stream->updates_cache, key, value);
                    }
                }
            }
        }
    } else {
        char ts[32];
        dslink_create_ts(ts, 32);
        json_object_set_new_nocheck(stream->updates_cache,
                                    "$disconnectedTs",
                                    json_string_nocheck(ts));
        stream->cache_sent = 0;
    }
}



