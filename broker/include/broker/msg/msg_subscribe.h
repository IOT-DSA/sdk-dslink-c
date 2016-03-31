#ifndef BROKER_MSG_SUBSCRIBE_H
#define BROKER_MSG_SUBSCRIBE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/node.h"
#include "broker/remote_dslink.h"

typedef struct PendingSub {
    const char *path;
    RemoteDSLink * requester;
    uint32_t reqSid;
    uint8_t qos;
    DownstreamNode *req;
    ListNode *listNode;
} PendingSub;

int broker_msg_handle_subscribe(RemoteDSLink *link, json_t *req);
void broker_handle_local_subscribe(BrokerNode *node,
                                   RemoteDSLink *link,
                                   uint32_t sid);

void broker_subscribe_remote(DownstreamNode *node, RemoteDSLink *link,
                             uint32_t sid, uint8_t qos, const char *path,
                             const char *respPath);
void broker_subscribe_disconnected_remote(RemoteDSLink *link,
                                          const char *path,
                                          uint32_t sid, uint8_t qos);

void broker_free_pending_sub(PendingSub* sub, uint8_t freeNode);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_SUBSCRIBE_H
