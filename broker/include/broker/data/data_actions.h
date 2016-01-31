#ifndef BROKER_DATA_ACTIONS_H
#define BROKER_DATA_ACTIONS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

BrokerNode *broker_data_create_add_node_action(BrokerNode *parent);
BrokerNode *broker_data_create_add_value_action(BrokerNode *parent);
BrokerNode *broker_data_create_publish_action(BrokerNode *parent);
BrokerNode *broker_data_create_delete_action(BrokerNode *parent);

#ifdef __cplusplus
}
#endif

#endif // BROKER_DATA_ACTIONS_H
