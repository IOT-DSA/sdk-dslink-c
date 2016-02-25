#ifndef BROKER_MSG_HANDLER_H
#define BROKER_MSG_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/broker.h"

void broker_msg_handle(RemoteDSLink *link, json_t *data);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_HANDLER_H
