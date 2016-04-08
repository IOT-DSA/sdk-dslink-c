#ifndef BROKER_MSG_LIST_H
#define BROKER_MSG_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/stream.h"
#include "broker/node.h"

int broker_msg_handle_list(RemoteDSLink *link, json_t *req);
void update_list_child(BrokerNode *node, BrokerListStream *stream, const char* name);
void update_list_attribute(BrokerNode *node, BrokerListStream *stream, const char *name, json_t *value);

int broker_list_req_closed(void *stream, RemoteDSLink *reqLink);
void broker_add_requester_list_stream(RemoteDSLink *reqLink,
                          BrokerListStream *stream, uint32_t reqRid);

void send_list_updates(RemoteDSLink *reqLink,
                       BrokerListStream *stream,
                       uint32_t reqRid);


void broker_list_dslink(RemoteDSLink *reqLink,
                        DownstreamNode *node,
                        const char *path,
                        uint32_t reqRid);

void broker_list_dslink_response(RemoteDSLink *link,
                                 json_t *resp,
                                 BrokerListStream *stream);

void broker_stream_list_disconnect(BrokerListStream *stream);
void broker_stream_list_connect(BrokerListStream *stream, DownstreamNode *node);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_LIST_H
