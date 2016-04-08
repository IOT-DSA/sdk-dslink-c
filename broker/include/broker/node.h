#ifndef BROKER_NODE_H
#define BROKER_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"

struct RemoteDSLink;
struct BrokerNode;
struct UpstreamPoll;
struct json_t;
struct Broker;

typedef void (*on_invocation_cb)(struct RemoteDSLink *link,
                                 struct BrokerNode *node,
                                 struct json_t *request,
                                 PermissionLevel maxPermission);

typedef enum BrokerNodeType {

    REGULAR_NODE = 0,
    DOWNSTREAM_NODE
} BrokerNodeType;

#define BROKER_NODE_FIELDS \
    BrokerNodeType type; \
    const char *path; \
    const char *name; \
    struct BrokerNode *parent; \
    Map *children; \
    List *permissionList; \
    json_t *meta

typedef struct BrokerNodeBase {
    BROKER_NODE_FIELDS;
} BrokerNodeBase;

typedef struct BrokerNode {

    BROKER_NODE_FIELDS;

    struct BrokerListStream *list_stream;
    struct BrokerSubStream *sub_stream;

    on_invocation_cb on_invoke;
    json_t *value;

    Dispatcher on_value_update;
    Dispatcher on_child_added;
    Dispatcher on_child_removed;
} BrokerNode;

// virtual permission node for downstream nodes
typedef struct VirtualDownstreamNode {
    List *permissionList;
    // Map<char *, VirtualDownstreamNode *>
    Map childrenNode;
    json_t *meta;
} VirtualDownstreamNode;

typedef struct DownstreamNode {

    BROKER_NODE_FIELDS;

    struct RemoteDSLink *link;

    ref_t *dsId;

    // Map<char *, Stream *>
    Map list_streams;

    uint32_t rid;
    uint32_t sid;

    // Map<char *, VirtualDownstreamNode *>
    Map children_permissions;

    struct UpstreamPoll *upstreamPoll;

    // Map<char *, BrokerSubStream *>
    Map resp_sub_streams;

    // Map<uint32_t *, BrokerSubStream *>
    Map resp_sub_sids;

    // Map<char *, SubRequester *>
    Map req_sub_paths;

    // Map<uint32_t *, SubRequester *>
    Map req_sub_sids;

} DownstreamNode;

BrokerNode *broker_node_get(BrokerNode *root,
                            const char *path, char **out);
BrokerNode *broker_node_create(const char *name, const char *profile);
BrokerNode *broker_node_createl(const char *name, size_t nameLen,
                                const char *profile, size_t profileLen);

// when newValue is 1, node won't add ref count on value
void  broker_node_update_value(BrokerNode *node, json_t *value, uint8_t isNewValue);

int broker_node_add(BrokerNode *parent, BrokerNode *child);

void broker_node_free(BrokerNode *node);

uint32_t broker_node_incr_rid(DownstreamNode *node);
uint32_t broker_node_incr_sid(DownstreamNode *node);

void broker_dslink_disconnect(DownstreamNode *node);
void broker_dslink_connect(DownstreamNode *node, struct RemoteDSLink *link);

// add a timer to save downstream nodes
void broker_downstream_nodes_changed(struct Broker *broker);
void broker_save_downstream_nodes(uv_timer_t* handle);
int broker_load_downstream_nodes(struct Broker *broker);
int broker_load_qos_storage(struct Broker *broker);
// add a timer to save data nodes
void broker_data_nodes_changed(struct Broker *broker);
void broker_save_data_nodes(uv_timer_t* handle);
int broker_load_data_nodes(struct Broker *broker);

void virtual_downstream_node_init(VirtualDownstreamNode *node);
void virtual_downstream_node_free(VirtualDownstreamNode *node);
// free a children map of virtual permissions
void virtual_downstream_free_map(Map *map);

// set attribute and return the node
// if key == NULL, only get the node
json_t *set_virtual_attribute(const char* path, VirtualDownstreamNode* node, const char *key, json_t *value);
json_t *set_downstream_attribute(const char* path, DownstreamNode* node, const char *key, json_t *value);

size_t broker_downstream_node_base_len(const char *path);
#ifdef __cplusplus
}
#endif

#endif // BROKER_NODE_H
