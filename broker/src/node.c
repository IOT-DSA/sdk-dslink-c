#include "broker/node.h"

uint32_t broker_node_incr_rid(DownstreamNode *node) {
    if (node->rid > (UINT32_MAX - 1)) {
        // Loop it around
        node->rid = 1;
    } else {
        node->rid++;
    }
    return node->rid;
}
