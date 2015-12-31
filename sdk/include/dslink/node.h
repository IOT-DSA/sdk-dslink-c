#ifndef SDK_DSLINK_C_NODE_H
#define SDK_DSLINK_C_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/col/map.h>
struct DSLink;

struct DSNode;
typedef struct DSNode DSNode;

typedef void (*node_event_cb)(struct DSLink *link, DSNode *node);

struct DSNode {
    const char *path;
    const char *name;
    const char *profile;

    // Used to store data such as configs and attributes
    // Only strings must be used as the value, otherwise
    // the usage is undefined.
    Map *meta_data;

    // Children of the node. Only DSNode values can be
    // here, otherwise the usage is undefined.
    Map *children;

    // Used to notify when the node has been listed.
    node_event_cb on_list_open;

    // Used to notify when the node list stream has been closed.
    node_event_cb on_list_close;
};

DSNode *dslink_node_create(DSNode *parent,
                           const char *name, const char *profile);
int dslink_node_add_child(DSNode *parent, DSNode *node);

DSNode *dslink_node_get_path(DSNode *root, const char *path);
void dslink_node_tree_free(DSNode *root);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_NODE_H
