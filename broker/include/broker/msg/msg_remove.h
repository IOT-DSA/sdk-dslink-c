#ifndef SDK_BROKER_MSG_REMOVE_H
#define SDK_BROKER_MSG_REMOVE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"

int broker_msg_handle_remove(RemoteDSLink *link, json_t *req);

#ifdef __cplusplus
}
#endif


#endif //SDK_BROKER_MSG_REMOVE_H
