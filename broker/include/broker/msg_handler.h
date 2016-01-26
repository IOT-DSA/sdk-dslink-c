#ifndef SDK_DSLINK_C_MSG_HANDLER_H
#define SDK_DSLINK_C_MSG_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "broker/broker.h"

void broker_handle_msg(Broker *broker, json_t *data);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_MSG_HANDLER_H
