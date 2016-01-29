#ifndef BROKER_DATA_H
#define BROKER_DATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"
#include "broker/node.h"

int data_node_populate(BrokerNode *data_node);

int data_node_add(BrokerNode *data_node, char *name);

#ifdef __cplusplus
}
#endif

#endif // BROKER_DATA_H
