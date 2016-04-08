#include <broker/sys/permission_action.h>
#include "broker/global.h"
#include "broker/query/query.h"
#include "broker/sys/sys.h"
#include "broker/sys/token.h"
#include "broker/sys/restart.h"
#include "broker/sys/clear_conns.h"
#include "broker/upstream/upstream_node.h"

#include "dslink/utils.h"

int init_sys_static(BrokerNode *sysNode) {
    BrokerNode *buildNode = broker_node_create("build_number", "node");
    BrokerNode *startTimeNode = broker_node_create("startTime", "node");
    BrokerNode *versionNode = broker_node_create("version", "node");

    if (!buildNode) {
        return 1;
    }

    if (broker_node_add(sysNode, buildNode) != 0) {
        broker_node_free(buildNode);
        return 1;
    }

    if (json_object_set_new(buildNode->meta, "$type",
                            json_string_nocheck("string")) != 0) {
        return 1;
    }

    if (json_object_set_new(buildNode->meta, "$name",
                            json_string_nocheck("Server Build")) != 0) {
        return 1;
    }

    if (broker_node_add(sysNode, versionNode) != 0) {
        broker_node_free(versionNode);
        return 1;
    }

    if (json_object_set_new(versionNode->meta, "$type",
                            json_string_nocheck("string")) != 0) {
        return 1;
    }

    if (json_object_set_new(versionNode->meta, "$name",
                            json_string_nocheck("DSA Version")) != 0) {
        return 1;
    }

    if (broker_node_add(sysNode, startTimeNode) != 0) {
        broker_node_free(startTimeNode);
        return 1;
    }

    if (json_object_set_new(startTimeNode->meta, "$type",
                            json_string_nocheck("string")) != 0) {
        return 1;
    }

    if (json_object_set_new(startTimeNode->meta, "$name",
                            json_string_nocheck("Start Time")) != 0) {
        return 1;
    }

    buildNode->value = json_string_nocheck(BROKER_SERVER_BUILD);
    versionNode->value = json_string_nocheck(BROKER_DSA_VERSION);

    {
        char ts[32];
        dslink_create_ts(ts, 32);
        startTimeNode->value = json_string_nocheck(ts);
    }

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
    init_clear_conns(sysNode);
    init_update_permissions_action(sysNode);
    return 0;
}
