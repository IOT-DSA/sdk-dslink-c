#ifndef SDK_DSLINK_C_MSG_CLOSE_H
#define SDK_DSLINK_C_MSG_CLOSE_H


#ifdef __cplusplus
extern "C" {
#endif

#include "broker/stream.h"
#include "broker/node.h"

void broker_send_close_request(RemoteDSLink *respLink,
                       uint32_t rid);




#ifdef __cplusplus
}
#endif

#endif //SDK_DSLINK_C_MSG_CLOSE_H
