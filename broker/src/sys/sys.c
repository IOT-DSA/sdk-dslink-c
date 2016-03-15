#include <broker/upstream/upstream_node.h>
#include "broker/sys/sys.h"
#include "broker/sys/token.h"
#include "broker/sys/restart.h"
#include "broker/query/query.h"
#include "broker/global.h"

int init_sys_static(BrokerNode *sysNode) {
    BrokerNode *buildNode = broker_node_create("build_number", "node");
    if (!buildNode) {
        return 1;
    }

    if (broker_node_add(sysNode, buildNode) != 0) {
        broker_node_free(buildNode);
        return 1;
    }

    if (json_object_set_new(buildNode->meta, "$type",
                            json_string("string")) != 0) {
        return 1;
    }

    if (json_object_set_new(buildNode->meta, "$name",
                            json_string("Server Build")) != 0) {
        return 1;
    }

    buildNode->value = json_string(BROKER_SERVER_BUILD);

    return 0;
}

int broker_sys_node_populate(BrokerNode *sysNode) {
    if (!sysNode) {
        return 1;
    }

    broker_query_create_action(sysNode);
    init_tokens(sysNode);
    init_restart(sysNode);
    init_sys_upstream_node(sysNode);
    init_sys_static(sysNode);
    return 0;
}
