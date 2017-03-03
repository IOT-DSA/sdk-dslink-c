#include <broker/sys/permission_action.h>
#include <broker/node.h>
#include <broker/utils.h>
#include <broker/broker.h>
#include <broker/net/ws.h>

static
void update_permissions(RemoteDSLink *link,
                 BrokerNode *node,
                 json_t *req, PermissionLevel maxPermission) {
    (void)node;
    if (maxPermission < PERMISSION_CONFIG) {
        broker_utils_send_closed_resp(link, req, "permissionDenied");
        return;
    }
    if (link && req) {
        json_t *params = json_object_get(req, "params");
        if (!json_is_object(params)) {
            broker_utils_send_closed_resp(link, req, "invalidParameter");
            return;
        }

        json_t *Path = json_object_get(params, "Path");
        json_t *Permissions = json_object_get(params, "Permissions");
        if (!(json_is_array(Permissions) && json_is_string(Path))) {
            broker_utils_send_closed_resp(link, req, "invalidParameter");
            return;
        }

        Broker *broker = mainLoop->data;

        if (set_permission_list(json_string_value(Path), broker->root, link, Permissions) != 0) {
            broker_utils_send_closed_resp(link, req, "permissionDenied");
            return;
        }


        broker_utils_send_closed_resp(link, req, NULL);
    }
}


static
void get_permissions(RemoteDSLink *link,
                        BrokerNode *node,
                        json_t *req, PermissionLevel maxPermission) {
    (void)node;
    if (maxPermission < PERMISSION_READ) {
        broker_utils_send_closed_resp(link, req, "permissionDenied");
        return;
    }
    if (link && req) {
        json_t *params = json_object_get(req, "params");
        if (!json_is_object(params)) {
            broker_utils_send_closed_resp(link, req, "invalidParameter");
            return;
        }

        json_t *Path = json_object_get(params, "Path");
        if (!json_is_string(Path)) {
            broker_utils_send_closed_resp(link, req, "invalidParameter");
            return;
        }

        Broker *broker = mainLoop->data;

        json_t * permissions = get_permission_list(json_string_value(Path),broker->root, link);
        if (!permissions) {
            permissions = json_null();
        }


        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_t *resp = json_object();
        json_array_append_new(resps, resp);

        json_t *rid = json_object_get(req, "rid");
        json_object_set_nocheck(resp, "rid", rid);
        json_object_set_new_nocheck(resp, "stream",
                                    json_string_nocheck("closed"));

        json_t *updates = json_array();
        json_t *row = json_array();
        json_array_append_new(updates, row);
        json_array_append_new(row, permissions);
        json_object_set_new_nocheck(resp, "updates", updates);

        broker_ws_send_obj(link, top);
        json_decref(top);
    }
}

int init_permissions_actions(BrokerNode *sysNode) {

// update permissions
    BrokerNode *updatePermissionsAction = broker_node_create("updatePermissions", "node");
    if (!updatePermissionsAction) {
        return 1;
    }

    if (broker_node_add(sysNode, updatePermissionsAction) != 0) {
        broker_node_free(updatePermissionsAction);
        return 1;
    }

    if (json_object_set_new_nocheck(updatePermissionsAction->meta, "$invokable",
                            json_string_nocheck("read")) != 0) {
        return 1;
    }

    if (json_object_set_new_nocheck(updatePermissionsAction->meta, "$name",
                            json_string_nocheck("Update Permissions")) != 0) {
        return 1;
    }

    json_error_t err;
    json_t *params = json_loads("[{\"name\":\"Path\",\"type\":\"string\"},{\"name\":\"Permissions\",\"type\":\"dynamic\"}]", 0, &err);
    if (json_object_set_new_nocheck(updatePermissionsAction->meta, "$params", params) != 0) {
        return 1;
    }

    updatePermissionsAction->on_invoke = update_permissions;


// get permissions
    BrokerNode *getPermissionsAction = broker_node_create("getPermissions", "node");
    if (!getPermissionsAction) {
        return 1;
    }

    if (broker_node_add(sysNode, getPermissionsAction) != 0) {
        broker_node_free(getPermissionsAction);
        return 1;
    }

    if (json_object_set_new_nocheck(getPermissionsAction->meta, "$invokable",
                                    json_string_nocheck("read")) != 0) {
        return 1;
    }

    if (json_object_set_new_nocheck(getPermissionsAction->meta, "$name",
                                    json_string_nocheck("Get Permissions")) != 0) {
        return 1;
    }


    params = json_loads("[{\"name\":\"Path\",\"type\":\"string\"}]", 0, &err);
    if (json_object_set_new_nocheck(getPermissionsAction->meta, "$params", params) != 0) {
        return 1;
    }


    json_t *columns = json_loads("[{\"name\":\"permission\",\"type\":\"string\"}]", 0, &err);
    if (json_object_set_new_nocheck(getPermissionsAction->meta, "$columns", columns) != 0) {
        return 1;
    }
    getPermissionsAction->on_invoke = get_permissions;

    return 0;
}
