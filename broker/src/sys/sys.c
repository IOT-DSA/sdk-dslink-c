#include <broker/sys/permission_action.h>
#include <broker/sys/throughput.h>
#include "broker/global.h"
#include "broker/query/query.h"
#include "broker/sys/sys.h"
#include "broker/sys/token.h"
#include "broker/sys/restart.h"
#include "broker/sys/clear_conns.h"
#include "broker/utils.h"
#include "broker/upstream/upstream_node.h"
#include "broker/net/ws.h"

#define LOG_TAG "sys"

#include <dslink/log.h>
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

    if (json_object_set_new_nocheck(buildNode->meta, "$type",
                            json_string_nocheck("string")) != 0) {
        return 1;
    }

    if (json_object_set_new_nocheck(buildNode->meta, "$name",
                            json_string_nocheck("Server Build")) != 0) {
        return 1;
    }

    if (broker_node_add(sysNode, versionNode) != 0) {
        broker_node_free(versionNode);
        return 1;
    }

    if (json_object_set_new_nocheck(versionNode->meta, "$type",
                            json_string_nocheck("string")) != 0) {
        return 1;
    }

    if (json_object_set_new_nocheck(versionNode->meta, "$name",
                            json_string_nocheck("DSA Version")) != 0) {
        return 1;
    }

    if (broker_node_add(sysNode, startTimeNode) != 0) {
        broker_node_free(startTimeNode);
        return 1;
    }

    if (json_object_set_new_nocheck(startTimeNode->meta, "$type",
                            json_string_nocheck("string")) != 0) {
        return 1;
    }

    if (json_object_set_new_nocheck(startTimeNode->meta, "$name",
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

static
void set_log_level(RemoteDSLink *link,
                   BrokerNode *node,
                   json_t *req,
                   PermissionLevel maxPermission)
{
    (void)node;
    if (maxPermission < PERMISSION_CONFIG) {
        broker_utils_send_closed_resp(link, req, "permissionDenied");
        return;
    }
    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        broker_utils_send_closed_resp(link, req, "invalidParameter");
        return;
    }

    json_t *level = json_object_get(params, "Level");
    if (!json_is_string(level)) {
        broker_utils_send_closed_resp(link, req, "invalidParameter");
        return;
    }

    const char* name = json_string_value(level);
    dslink_log_set_lvl(name);

  json_t* rid = json_object_get(req, "rid");
  if(!rid) {
    return;
  }

  json_t* top = json_object();
  if (!top) {
    return;
  }
  json_t* resps = json_array();
  if (!resps) {
    json_delete(top);
    return;
  }
  json_object_set_new_nocheck(top, "responses", resps);

  json_t* resp = json_object();
  if (!resp) {
    json_delete(top);
    return;
  }
  json_t* updates = json_array();
  json_t* update = json_array();
  json_array_append_new(updates, update);
  json_object_set_new_nocheck(resp, "updates", updates);
  json_array_append_new(resps, resp);

  json_object_set_new_nocheck(resp, "stream", json_string("closed"));
  json_object_set_nocheck(resp, "rid", rid);
  broker_ws_send_obj(link, top);
  json_delete(top);
}

int init_set_log_level(BrokerNode *sysNode)
{
    BrokerNode *setLogLevelNode = broker_node_create("setLogLevel", "node");
    if (!setLogLevelNode) {
        return 1;
    }

    if (broker_node_add(sysNode, setLogLevelNode) != 0) {
        broker_node_free(setLogLevelNode);
        return 1;
    }

    if (json_object_set_new_nocheck(setLogLevelNode->meta, "$invokable",
                                    json_string_nocheck("write")) != 0) {
        return 1;
    }

    if (json_object_set_new_nocheck(setLogLevelNode->meta, "$name",
                                    json_string_nocheck("Set Log Level")) != 0) {
        return 1;
    }

    setLogLevelNode->on_invoke = set_log_level;

    json_error_t err;
    json_t *params = json_loads("[{\"name\":\"Level\",\"type\":\"enum[off,fatal,error,warn,info,debug]\"}]", 0, &err);
    if (json_object_set_new_nocheck(setLogLevelNode->meta, "$params", params) != 0) {
        return 1;
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
    init_set_log_level(sysNode);
    init_permissions_actions(sysNode);
    init_throughput(sysNode);
    return 0;
}
