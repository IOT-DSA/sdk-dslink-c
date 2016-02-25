#ifndef BROKER_DATA_H
#define BROKER_DATA_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"

int broker_data_node_populate(BrokerNode *dataNode);
void broker_data_send_closed_resp(RemoteDSLink *link, json_t *req);
void create_dynamic_data_node(BrokerNode *node, const char *path,
                              json_t *value);

#ifdef __cplusplus
}
#endif

#endif // BROKER_DATA_H
