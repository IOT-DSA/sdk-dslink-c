#ifndef BROKER_MSG_LIST_H
#define BROKER_MSG_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "broker/broker.h"

int broker_msg_handle_list(Broker *broker, json_t *req);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_LIST_H
