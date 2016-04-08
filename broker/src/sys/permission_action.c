#include <broker/sys/permission_action.h>
#include <broker/node.h>
#include <broker/utils.h>
#include <broker/broker.h>

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

        if (set_permission(json_string_value(Path), broker->root, link, Permissions) != 0) {
            broker_utils_send_closed_resp(link, req, "permissionDenied");
            return;
        }


        broker_utils_send_closed_resp(link, req, NULL);
    }
}

int init_update_permissions_action(BrokerNode *sysNode) {
    BrokerNode *updatePermissionsAction = broker_node_create("updatePermissions", "node");
    if (!updatePermissionsAction) {
        return 1;
    }

    if (broker_node_add(sysNode, updatePermissionsAction) != 0) {
        broker_node_free(updatePermissionsAction);
        return 1;
    }

    if (json_object_set_new(updatePermissionsAction->meta, "$invokable",
                            json_string_nocheck("read")) != 0) {
        return 1;
    }

    if (json_object_set_new(updatePermissionsAction->meta, "$name",
                            json_string_nocheck("Update Permissions")) != 0) {
        return 1;
    }

    json_error_t err;
    json_t *params = json_loads("[{\"name\":\"Path\",\"type\":\"string\"},{\"name\":\"Permissions\",\"type\":\"dynamic\"}]", 0, &err);
    if (json_object_set_new(updatePermissionsAction->meta, "$params", params) != 0) {
        return 1;
    }

    updatePermissionsAction->on_invoke = update_permissions;

    return 0;
}
