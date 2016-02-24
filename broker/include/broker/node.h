#ifndef BROKER_NODE_H
#define BROKER_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"

struct BrokerNode;

typedef void (*on_invocation_cb)(struct RemoteDSLink *link,
                                 struct BrokerNode *node,
                                 json_t *request);

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
    json_t *meta

typedef struct BrokerNodeBase {
    BROKER_NODE_FIELDS;
} BrokerNodeBase;

typedef struct BrokerNode {

    BROKER_NODE_FIELDS;

    struct BrokerListStream *list_stream;
    on_invocation_cb on_invoke;
    json_t *value;

    Dispatcher on_value_update;
    Dispatcher on_child_added;
    Dispatcher on_child_removed;
    Dispatcher on_list_update;
} BrokerNode;

typedef struct DownstreamNode {

    BROKER_NODE_FIELDS;

    struct RemoteDSLink *link;

    // Map<char *, Stream *>
    Map list_streams;

    Dispatcher on_link_connect;
    Dispatcher on_link_disconnect;

    ref_t *dsId;
    uint32_t rid;
    uint32_t sid;

} DownstreamNode;

BrokerNode *broker_node_get(BrokerNode *root,
                            const char *path, char **out);
BrokerNode *broker_node_create(const char *name, const char *profile);
BrokerNode *broker_node_createl(const char *name, size_t nameLen,
                                const char *profile, size_t profileLen);

// when newValue is 1, node won't add ref count on value
void  broker_node_update_value(BrokerNode *node, json_t *value, uint8_t isNewValue);

int broker_node_add(BrokerNode *parent, BrokerNode *child);
// update all the listener and stream of the children change
// the change could be adding or removing
void broker_node_update_child(BrokerNode *parent, const char* name);

void broker_node_free(BrokerNode *node);

uint32_t broker_node_incr_rid(DownstreamNode *node);
uint32_t broker_node_incr_sid(DownstreamNode *node);

void broker_dslink_disconnect(DownstreamNode *node);
void broker_dslink_connect(DownstreamNode *node, RemoteDSLink *link);

#ifdef __cplusplus
}
#endif

#endif // BROKER_NODE_H
