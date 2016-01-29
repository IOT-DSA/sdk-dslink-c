#ifndef BROKER_DATA_H
#define BROKER_DATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"
#include "broker/node.h"

int broker_data_node_populate(BrokerNode *dataNode);
int data_node_add(BrokerNode *data_node, char *name);

#ifdef __cplusplus
}
#endif

#endif // BROKER_DATA_H
