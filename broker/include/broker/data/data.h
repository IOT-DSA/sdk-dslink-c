#ifndef BROKER_DATA_H
#define BROKER_DATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

struct Broker;

int broker_data_node_populate(BrokerNode *dataNode);
void broker_data_node_update(BrokerNode *node,
                             json_t *value,
                             uint8_t isNewValue);
void broker_create_dynamic_data_node(struct Broker *broker, BrokerNode *node, const char *path,
                                     json_t *value, uint8_t serialize);

int broker_create_data_actions(BrokerNode *node);

#ifdef __cplusplus
}
#endif

#endif // BROKER_DATA_H
