#ifndef BROKER_STREAM_H
#define BROKER_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/stream.h>
#include <dslink/col/list.h>
#include <dslink/col/map.h>

#include "broker/remote_dslink.h"

struct BrokerNode;

typedef void (*continuous_invoke_cb)(RemoteDSLink *link, json_t *params);
typedef void (*invoke_close_cb)(void *stream);
typedef int (*stream_close_cb)(void *stream, RemoteDSLink *link);

#define BROKER_STREAM_FIELDS \
    StreamType type; \
    stream_close_cb req_close_cb; \
    stream_close_cb resp_close_cb


typedef struct BrokerStream {

    BROKER_STREAM_FIELDS;

} BrokerStream;

typedef struct BrokerListStream {

    BROKER_STREAM_FIELDS;

    struct BrokerNodeBase *node;
    char *remote_path;
    uint32_t responder_rid;

    // JSON object of all the updates
    json_t *updates_cache;

    // Map<RemoteDSLink *, uint32_t *>
    Map requester_links;

    uint8_t cache_sent;

} BrokerListStream;

typedef struct BrokerInvokeStream {

    BROKER_STREAM_FIELDS;

    RemoteDSLink *requester;
    RemoteDSLink *responder;
    continuous_invoke_cb continuous_invoke;
    uint32_t requester_rid;
    uint32_t responder_rid;

    void *data;
} BrokerInvokeStream;

typedef struct BrokerSubStream {

    BROKER_STREAM_FIELDS;

    struct BrokerNode *respNode;
    uint32_t respSid;
    uint8_t respQos;

    char *remote_path;


    json_t *last_value;

    // Map<DownstreamNode *, SubClient *>
    Map reqSubs;

} BrokerSubStream;

BrokerListStream *broker_stream_list_init(void *node);
BrokerInvokeStream *broker_stream_invoke_init();
BrokerSubStream *broker_stream_sub_init();

void requester_stream_closed(BrokerStream *stream, RemoteDSLink *link);
void responder_stream_closed(BrokerStream * stream, RemoteDSLink *link);
void broker_stream_free(BrokerStream *stream);
json_t *broker_stream_list_get_cache(BrokerListStream *stream);
void broker_stream_list_reset_remote_cache(BrokerListStream *stream, RemoteDSLink *link);


#ifdef __cplusplus
}
#endif

#endif // BROKER_STREAM_H
