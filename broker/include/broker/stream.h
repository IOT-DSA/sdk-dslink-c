#ifndef BROKER_STREAM_H
#define BROKER_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/col/list.h>
#include <dslink/col/map.h>
#include <dslink/stream.h>

typedef struct BrokerStream {

    StreamType type;

} BrokerStream;

typedef struct BrokerListStream {

    StreamType type;

    // JSON array of all the updates
    json_t *updates_cache;

    // Map<uint32_t *, RemoteDSLink *>
    Map clients;

} BrokerListStream;

BrokerListStream *broker_stream_list_init();
void broker_stream_free(BrokerStream *stream);
json_t *broker_stream_list_get_cache(BrokerListStream *stream);

#ifdef __cplusplus
}
#endif

#endif // BROKER_STREAM_H
