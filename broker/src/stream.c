#include <stdlib.h>
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

    return stream;
}
