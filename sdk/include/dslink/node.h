#ifndef SDK_DSLINK_C_NODE_H
#define SDK_DSLINK_C_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "dslink/col/map.h"

struct DSLink;

struct DSNode;
typedef struct DSNode DSNode;

typedef void (*node_event_cb)(struct DSLink *link, DSNode *node);
typedef void (*node_value_set_cb)(struct DSLink *link, DSNode *node, json_t *value);
typedef void (*node_action_cb)(struct DSLink *link, DSNode *node,
                               json_t *rid, json_t *params, ref_t *stream);

typedef void (*dslink_stream_close_cb)(struct DSLink *link, DSNode *node, void *stream);

struct DSNode {
    const char *path;
    const char *name;
    const char *profile;

    DSNode *parent;

    // Used to store data such as configs and attributes
    // Only strings must be used as the value, otherwise
    // the usage is undefined.
    Map *meta_data;

    // Children of the node. Only DSNode values can be
    // here, otherwise the usage is undefined.
    Map *children;

    // The timestamp of the value. This must be a formatted
    // string.
    json_t *value_timestamp;

    // The value of the node. This is used when the node
    // gets subscribed to.
    json_t *value;

    // Notification callback when the node is listed.
    node_event_cb on_list_open;

    // Notification callback when the node is closed.
    dslink_stream_close_cb on_list_close;

    // Notification callback when the node is subscribed.
    node_event_cb on_subscribe;

    // Notification callback when the node is unsubscribed.
    node_event_cb on_unsubscribe;

    // Notification callback when the node metadata or value is changed
    node_event_cb on_data_changed;

    // Invocation callback.
    node_action_cb on_invocation;
    
    // Value set callback.
    node_value_set_cb on_value_set;

    // Reference to a data object for convenience.
    ref_t *data;

    uint8_t serializable;
};

DSNode *dslink_node_create(DSNode *parent,
                           const char *name, const char *profile);
int dslink_node_add_child(struct DSLink *link, DSNode *node);

DSNode *dslink_node_get_path(DSNode *root, const char *path);

// Remove a node and all its children from the link.
void dslink_node_remove(struct DSLink* link, DSNode* node);

// Depricated
void dslink_node_tree_free(struct DSLink *link, DSNode *root);

int dslink_node_set_meta(struct DSLink *link, DSNode *node, const char *name, json_t *value);
int dslink_node_set_meta_new(struct DSLink *link, DSNode *node, const char *name, json_t *value);
json_t * dslink_node_get_meta(DSNode *node, const char *name);

// deprecated, use dslink_node_update_value_new
int dslink_node_set_value(struct DSLink *link, DSNode *node, json_t *value);

int dslink_node_update_value(struct DSLink *link, DSNode *node, json_t *value);
int dslink_node_update_value_new(struct DSLink *link, DSNode *node, json_t *value);

json_t *dslink_node_serialize(struct DSLink *link, DSNode *node);
void dslink_node_deserialize(struct DSLink *link, DSNode *node, json_t *data);

// Thread-safe API
/*
 * @param path           path to the node
 * @param callback       a callback when the update is done, will be called from dslink's thread, parameters pass back in the callback will be (error, callback_data)
 * @param callback_data  a data that will be passed back to callback
 */
int dslink_node_update_value_safe(struct DSLink *link, char* path, json_t *value,  void (*callback)(int, void*), void * callback_data);

/*
 * @param path           path to the node
 * @param callback       a callback when the update is done, will be called from dslink's thread, parameters pass back in the callback will be (value, callback_data)
 * @param callback_data  a data that will be passed back to callback
 */
int dslink_node_get_value_safe(struct DSLink *link, char* path,  void (*callback)(json_t *, void*), void * callback_data);

/*
 * a thread safe api to run any other dslink api
 *
 * @param callback       a callback when the update is done, will be called from dslink's thread, parameters pass back in the callback will be (link, callback_data)
 * @param callback_data  a data that will be passed back to callback
 */
int dslink_run_safe(struct DSLink *link, void (*callback)(struct DSLink *link, void*), void * callback_data);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_NODE_H
