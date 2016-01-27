#include "broker/node.h"

void broker_dsnode_incr_rid(DownstreamNode *node) {
    if (node->rid > (UINT32_MAX - 1)) {
        // Loop it around
        node->rid = 1;
    } else {
        node->rid++;
    }
}
