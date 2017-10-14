#ifndef BROKER_REMOTE_DSLINK_H
#define BROKER_REMOTE_DSLINK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <jansson.h>
#include <wslay/wslay.h>

#include <dslink/col/map.h>
#include <dslink/col/listener.h>
#include <dslink/socket.h>
#include <dslink/crypto.h>

#include "broker/net/server.h"
#include "broker/permission/permission.h"

//comment out to disable sending ws messages in thread
#define BROKER_WS_SEND_THREAD_MODE
//#define BROKER_DROP_MESSAGE
//#define BROKER_WS_SEND_HYBRID_MODE // DO NOT USE!
//#define BROKER_WS_DIRECT_SEND

//#define BROKER_PING_THREAD // DO NOT USE!


typedef struct RemoteAuth {

    char salt[48];
    dslink_ecdh_context tempKey;
    const char *pubKey;

} RemoteAuth;

typedef struct RemoteDSLink {
    uint8_t isUpstream;
    uint8_t isRequester;
    uint8_t isResponder;
    uint8_t pendingClose;

    uint32_t msgId;

    struct timeval *lastWriteTime;

    uv_timer_t *pingTimerHandle;

    struct timeval *lastReceiveTime;

    wslay_event_context_ptr ws;
    Client *client;

    struct Broker *broker;
    struct DownstreamNode *node;
    RemoteAuth *auth;

    // char *
    ref_t *dsId;
    const char *path;
    const char *name;

    json_t *linkData;

    // Map<uint32_t *, Stream *>

    // connect to requester
    // broker receive requests and send back responses
    Map requester_streams;
    // connect to responder
    // broker send requests and receive responses
    Map responder_streams;

    PermissionGroups permission_groups;

    // Map<char *, SubRequester *>
    Map req_sub_paths;

    // Map<uint32_t *, SubRequester *>
    Map req_sub_sids;

    json_t* updates;

    uint32_t rid;


    int is_msgpack;
} RemoteDSLink;

int broker_remote_dslink_init(RemoteDSLink *link);
void broker_remote_dslink_free(RemoteDSLink *link);

#ifdef __cplusplus
}
#endif

#endif // BROKER_REMOTE_DSLINK_H
