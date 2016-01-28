#ifndef BROKER_MSG_LIST_H
#define BROKER_MSG_LIST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "broker/remote_dslink.h"

int broker_msg_handle_list(RemoteDSLink *link, json_t *req);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_LIST_H
