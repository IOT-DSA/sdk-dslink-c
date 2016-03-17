#ifndef BROKER_MSG_SUBSCRIBE_H
#define BROKER_MSG_SUBSCRIBE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"
#include "broker/node.h"

typedef struct PendingSub {

    const char *path;
    uint32_t reqSid;
    DownstreamNode *req;

} PendingSub;

int broker_msg_handle_subscribe(RemoteDSLink *link, json_t *req);
void broker_handle_local_subscribe(BrokerNode *node,
                                   RemoteDSLink *link,
                                   uint32_t sid);

void broker_subscribe_remote(DownstreamNode *node, RemoteDSLink *link,
                             uint32_t sid, const char *path,
                             const char *respPath);
void broker_subscribe_disconnected_remote(RemoteDSLink *link,
                                          const char *path,
                                          uint32_t sid);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_SUBSCRIBE_H
