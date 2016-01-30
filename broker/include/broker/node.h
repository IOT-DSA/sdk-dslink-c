#ifndef BROKER_NODE_H
#define BROKER_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef enum BrokerNodeType {

    REGULAR_NODE = 0,
    DOWNSTREAM_NODE

} BrokerNodeType;

#define BROKER_NODE_FIELDS \
    BrokerNodeType type; \
    const char *name; \
    struct BrokerNode *parent; \
    Map *children; \
    json_t *meta

typedef struct BrokerNode {

    BROKER_NODE_FIELDS;

    struct BrokerListStream *list_stream;

} BrokerNode;

typedef struct DownstreamNode {

    BROKER_NODE_FIELDS;

    struct RemoteDSLink *link;

    // Map<char *, Stream *>
    Map list_streams;

    const char *dsId;
    uint32_t rid;


} DownstreamNode;

BrokerNode *broker_node_get(BrokerNode *root,
                            const char *path, char **out);
BrokerNode *broker_node_create(const char *name, const char *profile);
int broker_node_add(BrokerNode *parent, BrokerNode *child);
void broker_node_free(BrokerNode *node);

uint32_t broker_node_incr_rid(DownstreamNode *node);

#ifdef __cplusplus
}
#endif

#endif // BROKER_NODE_H
