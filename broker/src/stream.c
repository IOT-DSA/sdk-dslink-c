#include <stdlib.h>
#include <string.h>
#include <dslink/utils.h>
#include <dslink/mem/mem.h>
#include "broker/stream.h"

BrokerListStream *broker_stream_list_init() {
    BrokerListStream *stream = dslink_calloc(1, sizeof(BrokerListStream));
    if (!stream) {
        return NULL;
    }

    stream->type = LIST_STREAM;
    listener_init(&stream->on_destroy);

    if (dslink_map_init(&stream->requester_links, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal) != 0) {
        dslink_free(stream);
        return NULL;
    }


    stream->updates_cache = json_object();
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
    listener_init(&stream->on_destroy);

    if (dslink_map_init(&stream->clients, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal) != 0) {
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
    listener_init(&stream->on_destroy);
    return stream;
}

void broker_stream_free(BrokerStream *stream) {
    if (!stream) {
        return;
    }

    if (stream->type == LIST_STREAM) {
        BrokerListStream *s = (BrokerListStream *) stream;
        if (s->requester_links.size > 0) {
            // don't free it when there is any other attached dslink
            return;
        }
        dslink_free(s->remote_path);
        json_decref(s->updates_cache);
    }
    dslink_free(stream);
}

static inline
void add_to_update(json_t *updates, const char *key, json_t *value) {
    json_t *update = json_array();

    // name
    json_array_append_new(update, json_string(key));
    //value
    json_array_append(update, value);

    json_array_append_new(updates, update);
}

json_t *broker_stream_list_get_cache(BrokerListStream *stream) {
    // TODO: check allocation

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

void broker_stream_list_reset_remote_cache(BrokerListStream *stream, RemoteDSLink *link) {
    json_object_clear(stream->updates_cache);
    if (link) {
        json_object_set_new_nocheck(stream->updates_cache,
                                    "$base", json_string_nocheck(link->path));
        if (strcmp(stream->remote_path, "/") == 0
            && link->linkData) {
            // add linkData into the updates_cache
            json_object_set_nocheck(stream->updates_cache,
                                    "$linkData", link->linkData);
        }
    } else {
        char ts[32];
        dslink_create_ts(ts, 32);
        json_object_set_new_nocheck(stream->updates_cache,
                                    "$disconnectedTs", json_string_nocheck(ts));
        stream->cache_sent = 0;
    }
}
