#ifndef BROKER_STREAM_H
#define BROKER_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/col/list.h>
#include <dslink/col/map.h>
#include <dslink/stream.h>

#include "broker/remote_dslink.h"

#define BROKER_STREAM_FIELDS \
    StreamType type

typedef void (*continuous_invoke_cb)(RemoteDSLink *link, json_t *params);
typedef void (*invoke_close_cb)(struct BrokerInvokeStream *stream);

typedef struct BrokerStream {

    BROKER_STREAM_FIELDS;

} BrokerStream;

typedef struct BrokerListStream {

    BROKER_STREAM_FIELDS;

    char *remote_path;

    uint32_t responder_rid;

    // JSON object of all the updates
    json_t *updates_cache;

    // Map<uint32_t *, RemoteDSLink *>
    Map clients;

    uint8_t cache_sent;

} BrokerListStream;

typedef struct BrokerInvokeStream {

    BROKER_STREAM_FIELDS;

    RemoteDSLink *requester;
    continuous_invoke_cb continuous_invoke;
    uint32_t requester_rid;

    void *data;
    invoke_close_cb close_cb;
} BrokerInvokeStream;

BrokerListStream *broker_stream_list_init();
BrokerInvokeStream *broker_stream_invoke_init();

void broker_stream_free(BrokerStream *stream);
json_t *broker_stream_list_get_cache(BrokerListStream *stream);
void broker_stream_list_reset_remote_cache(BrokerListStream *stream, RemoteDSLink *link);

#ifdef __cplusplus
}
#endif

#endif // BROKER_STREAM_H
