#ifndef BROKER_NODE_H
#define BROKER_NODE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct DownstreamNode {

    struct RemoteDSLink *link;

    const char *name;
    const char *dsId;

    uint32_t rid;

} DownstreamNode;

void broker_dsnode_incr_rid(DownstreamNode *node);

#ifdef __cplusplus
}
#endif

#endif // BROKER_NODE_H
