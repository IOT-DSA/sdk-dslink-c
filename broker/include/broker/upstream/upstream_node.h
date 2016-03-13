#ifndef BROKER_UPSTREAM_UPSTREAM_NODE_H
#define BROKER_UPSTREAM_UPSTREAM_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

int broker_upstream_node_populate(BrokerNode *upstreamNode);

int init_sys_upstream_node(BrokerNode *sysNode);

#ifdef __cplusplus
}
#endif

#endif // BROKER_UPSTREAM_UPSTREAM_NODE_H
