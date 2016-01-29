#ifndef BROKER_MSG_INVOKE_H
#define BROKER_MSG_INVOKE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"

int broker_msg_handle_invoke(RemoteDSLink *link, json_t *req);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_INVOKE_H
