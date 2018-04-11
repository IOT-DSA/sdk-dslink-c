#ifndef SDK_DSLINK_C_DSLINK_H
#define SDK_DSLINK_C_DSLINK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <mbedtls/ecdh.h>
#include <uv.h>

#include "socket.h"
#include "node.h"
#include "url.h"

typedef struct DSLinkCallbacks DSLinkCallbacks;
typedef struct DSLinkConfig DSLinkConfig;
typedef struct DSLink DSLink;
typedef struct Responder Responder;
typedef struct Requester Requester;

typedef void (*link_callback)(DSLink *link);
//thread-safe API callback definitions
typedef void (*async_set_callback)(int, void*);
typedef void (*async_get_callback)(json_t *, void*);
typedef void (*async_run_callback)(DSLink *link, void*);

struct DSLinkConfig {
    Url *broker_url;
    const char *name;
    const char *token;
};

struct DSLink {
    uint8_t is_requester;
    uint8_t is_responder;

    int closing;
    int closingSendThread;

    struct wslay_event_context *_ws; // Event context for WSLay
    Socket *_socket; // Socket for the _ws connection
    struct timeval lastReceiveTime;

    Requester *requester;
    Responder *responder; // Responder, only initialized for responder DSLinks
    mbedtls_ecdh_context key; // ECDH key
    uv_loop_t loop; // Primary event loop
    uv_async_t async_tasks; // async run
    uv_poll_t*  poll;
    DSLinkConfig config; // Configuration
    uint32_t *msg;

    json_t *link_data;
    json_t *dslink_json;
};

struct Responder {
    DSNode *super_root; // Super root, or "/" of the responder

    // Key is the integer RID, value is a Stream
    Map *open_streams;

    // Key is the path of the subscription, the value must be an integer
    // which is the RID to send an update back to.
    Map *list_subs;

    // Key is the path of the subscription, the value must be an integer
    // which is the SID to send update back to.
    Map *value_path_subs;

    // Key is the SID of the subscription, the value must be a string
    // which is the path of the node.
    Map *value_sid_subs;
};

struct Requester {
    uint32_t *rid;
    uint32_t *sid;
    Map *request_handlers;
    Map *list_subs;
    // Map<uint32*, Stream*>
    Map *open_streams;
    Map *value_handlers;
};

struct DSLinkCallbacks {
    link_callback init_cb;
    link_callback on_connected_cb;
    link_callback on_disconnected_cb;
    link_callback on_requester_ready_cb;
};

int dslink_init(int argc, char **argv,
                const char *name, uint8_t isRequester,
                uint8_t isResponder, DSLinkCallbacks *cbs);

json_t *dslink_read_dslink_json();
json_t *dslink_json_raw_get_config(json_t *json, const char *key);
json_t *dslink_json_get_config(DSLink *link, const char *key);

void dslink_close(DSLink *link);

int dslink_handle_key(DSLink *link);

// Save the current state of the link. 
// Store node hirarchy (except the action nodes) into the file nodes.json
// Return 0 on sucess or errror code defined in err.h on failure.
int dslink_save_nodes(DSLink *link);

// Load the last state of the link from the file nodes.json and put nodes below the responders root node
// The nodes are added to the link responder root node and to the link.
// Return 0 on sucess or errror code defined in err.h on failure.
int dslink_load_nodes(DSLink *link);

// Thread-safe API
/*
 * @param path           path to the node
 * @param callback       a callback when the update is done, will be called from dslink's thread, parameters pass back in the callback will be (error, callback_data)
 * @param callback_data  a data that will be passed back to callback
 */
int dslink_node_update_value_safe(struct DSLink *link, char* path, json_t *value,  async_set_callback callback, void * callback_data);

/*
 * @param path           path to the node
 * @param callback       a callback when the update is done, will be called from dslink's thread, parameters pass back in the callback will be (value, callback_data)
 * @param callback_data  a data that will be passed back to callback
 */
int dslink_node_get_value_safe(struct DSLink *link, char* path, async_get_callback callback, void * callback_data);

/*
 * a thread safe api to run any other dslink api
 *
 * @param callback       a callback when the update is done, will be called from dslink's thread, parameters pass back in the callback will be (link, callback_data)
 * @param callback_data  a data that will be passed back to callback
 */
int dslink_run_safe(struct DSLink *link, async_run_callback callback, void * callback_data);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_DSLINK_H
