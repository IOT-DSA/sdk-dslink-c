//
// Created by rinick on 12/03/16.
//

#ifndef SDK_DSLINK_C_UPSTREAM_NODE_H
#define SDK_DSLINK_C_UPSTREAM_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

int broker_upstream_node_populate(BrokerNode *upstreamNode);

int init_sys_upstream_node(BrokerNode *sysNode);

#ifdef __cplusplus
}
#endif

#endif //SDK_DSLINK_C_UPSTREAM_NODE_H
