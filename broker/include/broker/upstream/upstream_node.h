#ifndef BROKER_UPSTREAM_UPSTREAM_NODE_H
#define BROKER_UPSTREAM_UPSTREAM_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

struct UpstreamPoll;
struct Broker;

int broker_upstream_node_populate(BrokerNode *upstreamNode);

int init_sys_upstream_node(BrokerNode *sysNode);


DownstreamNode *create_upstream_node(struct Broker *broker, const char *name);

void init_upstream_node(struct Broker *broker, struct UpstreamPoll *upstreamPoll);



#ifdef __cplusplus
}
#endif

#endif // BROKER_UPSTREAM_UPSTREAM_NODE_H
