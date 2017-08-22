#ifndef BROKER_UPSTREAM_UPSTREAM_NODE_H
#define BROKER_UPSTREAM_UPSTREAM_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

#define UPSTREAM_ACTION_NONE 0
#define UPSTREAM_ACTION_DELETE 1
#define UPSTREAM_ACTION_RESET 2
#define UPSTREAM_ACTION_STOP 4


struct UpstreamPoll;
struct Broker;

int broker_upstream_node_populate(BrokerNode *upstreamNode);

int init_sys_upstream_node(BrokerNode *sysNode);


DownstreamNode *create_upstream_node(struct Broker *broker, const char *name);

void init_upstream_node(struct Broker *broker, struct UpstreamPoll *upstreamPoll, uv_timer_cb upstream_ping_handler);
void delete_upstream(struct UpstreamPoll *upstreamPoll);
#ifdef __cplusplus
}
#endif

#endif // BROKER_UPSTREAM_UPSTREAM_NODE_H
