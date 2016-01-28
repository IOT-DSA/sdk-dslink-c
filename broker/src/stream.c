#include <stdlib.h>
#include <dslink/utils.h>
#include "broker/stream.h"

BrokerListStream *broker_stream_list_init() {
    BrokerListStream *stream = calloc(1, sizeof(BrokerListStream));
    if (!stream) {
        return NULL;
    }

    stream->type = LIST_STREAM;
    if (dslink_map_init(&stream->clients, dslink_map_uint32_cmp,
                        dslink_map_uint32_key_len_cal) != 0) {
        free(stream);
        return NULL;
    }

    stream->updates_cache = json_object();
    if (!stream->updates_cache) {
        free(stream);
        return NULL;
    }

    return stream;
}

void broker_stream_free(BrokerStream *stream) {
    if (!stream) {
        return;
    }

    if (stream->type == LIST_STREAM) {
        BrokerListStream *s = (BrokerListStream *) stream;
        DSLINK_CHECKED_EXEC(json_decref, s->updates_cache);
    }
    free(stream);
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

    json_object_foreach(stream->updates_cache, key, value) {
        json_t *update = json_array();

        // name
        json_array_append_new(update, json_string(key));
        //value
        json_array_append(update, value);

        json_array_append_new(updates, update);
    }
    return updates;
}
