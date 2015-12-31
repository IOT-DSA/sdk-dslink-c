#ifndef SDK_DSLINK_C_DSLINK_H
#define SDK_DSLINK_C_DSLINK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>
#include "event_loop.h"
#include "socket.h"
#include "node.h"

typedef struct DSLinkCallbacks DSLinkCallbacks;
typedef struct DSLinkConfig DSLinkConfig;
typedef struct DSLink DSLink;
typedef struct Responder Responder;

typedef void (*link_callback)(DSLink *link);

struct DSLinkConfig {
    const char *broker_url;
    const char *name;
};

struct DSLink {
    uint32_t _delay; // Delay used in the I/O handler
    wslay_event_context_ptr _ws; // Event context for WSLay
    Socket *_socket; // Socket for the _ws connection

    Responder *responder; // Responder, only initialized for responder DSLinks
    EventLoop loop; // Primary event loop
};

struct Responder {
    DSNode *super_root; // Super root, or "/" of the responder

    // Key is the integer RID, value is a Stream
    Map *open_streams;

    // Key is the path of the subscription, the value must be an integer
    // which is the RID to send an update back to.
    Map *list_subs;
};

struct DSLinkCallbacks {
    link_callback init_cb;
    link_callback on_connected_cb;
    link_callback on_disconnected_cb;
};

int dslink_init(int argc, char **argv,
                const char *name, uint8_t isRequester,
                uint8_t isResponder, DSLinkCallbacks *cbs);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_DSLINK_H
