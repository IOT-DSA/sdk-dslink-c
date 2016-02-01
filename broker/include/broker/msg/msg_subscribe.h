#ifndef BROKER_MSG_SUBSCRIBE_H
#define BROKER_MSG_SUBSCRIBE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "broker/remote_dslink.h"

int broker_msg_handle_subscribe(RemoteDSLink *link, json_t *req);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_SUBSCRIBE_H
