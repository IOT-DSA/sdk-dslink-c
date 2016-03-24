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

    // Invocation callback.
    node_action_cb on_invocation;
};

DSNode *dslink_node_create(DSNode *parent,
                           const char *name, const char *profile);
int dslink_node_add_child(struct DSLink *link, DSNode *node);

DSNode *dslink_node_get_path(DSNode *root, const char *path);
void dslink_node_tree_free(struct DSLink *link, DSNode *root);

int dslink_node_set_meta(struct DSLink *link, DSNode *node, const char *name, json_t *value);
int dslink_node_set_value(struct DSLink *link, DSNode *node, json_t *value);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_NODE_H
