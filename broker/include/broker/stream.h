#ifndef BROKER_STREAM_H
#define BROKER_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/col/map.h>
#include <dslink/stream.h>

typedef struct BrokerStream {

    StreamType type;

} BrokerStream;

typedef struct BrokerListStream {

    StreamType type;

    // Map<uint32_t *, RemoteDSLink *>
    Map clients;

} BrokerListStream;

BrokerListStream *broker_stream_list_init();

#ifdef __cplusplus
}
#endif

#endif // BROKER_STREAM_H
