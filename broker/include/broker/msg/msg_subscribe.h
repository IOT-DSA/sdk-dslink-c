#ifndef BROKER_MSG_SUBSCRIBE_H
#define BROKER_MSG_SUBSCRIBE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"
#include "broker/remote_dslink.h"

struct SubRequester;
struct Broker;

int broker_msg_handle_subscribe(RemoteDSLink *link, json_t *req);
void broker_handle_local_subscribe(BrokerNode *respNode,
                                   struct SubRequester *subreq);

void broker_subscribe_remote(DownstreamNode *respNode, struct SubRequester *subreq,
                             const char *respPath);
void broker_subscribe_disconnected_remote(const char *path,
                                          struct SubRequester *subreq);

void broker_add_new_subscription(struct Broker *broker, struct SubRequester *subreq);

void broker_subscribe_disconnected_remote(const char *path, struct SubRequester *subreq);
void broker_subscribe_local_nonexistent(const char *path, struct SubRequester *subreq);



#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_SUBSCRIBE_H
