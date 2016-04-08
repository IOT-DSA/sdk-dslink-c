#include <broker/msg/msg_remove.h>

#include <dslink/utils.h>
#include <broker/utils.h>
#include <string.h>
#include <broker/msg/msg_list.h>
#include "broker/data/data.h"
#include "broker/net/ws.h"
#include "broker/broker.h"

int broker_msg_handle_remove(RemoteDSLink *link, json_t *req) {
    const char *path = json_string_value(json_object_get(req, "path"));
    json_t *rid = json_object_get(req, "rid");
    if (!(path && rid)) {
        return 1;
    }

    const char * name = strrchr(path, '/') + 1;
    if (*name != '@') {
        // not attribute
        broker_utils_send_closed_resp(link, req, "invalidParameter");
        return 0;
    }
    // value remove
    char *nodePath = dslink_strdupl(path, name-path-1);

    char *out = NULL;

    BrokerNode *node = broker_node_get(link->broker->root, nodePath, &out);

    {
        json_t *maxPermitJson = json_object_get(req, "permit");
        PermissionLevel maxPermit = PERMISSION_CONFIG;
        if (json_is_string(maxPermitJson)) {
            maxPermit = permission_str_level(json_string_value(maxPermitJson));
        }

        PermissionLevel permissionOnPath = get_permission(path, link->broker->root, link);
        if (permissionOnPath > maxPermit) {
            permissionOnPath = maxPermit;
        }

        if (permissionOnPath < PERMISSION_WRITE) {
            broker_utils_send_closed_resp(link, req, "permissionDenied");
            return 0;
        }
    }



    if (node && node->type == DOWNSTREAM_NODE) {
        if (set_downstream_attribute(out + 1, (DownstreamNode*)node, name, NULL)) {
            ref_t *ref = dslink_map_get(&((DownstreamNode*)node)->list_streams, out);
            if (ref) {
                BrokerListStream *liststream = ref->data;
                update_list_attribute(node, liststream, name, NULL);
            }
            broker_downstream_nodes_changed(link->broker);
        }
    } else if (node) {
        json_object_del(node->meta, name);
        if (node->list_stream) {
            update_list_attribute(node, node->list_stream, name, NULL);
        }
        if (dslink_str_starts_with(path, "/data")) {
            broker_data_nodes_changed(link->broker);
        }
    }

    dslink_free(nodePath);
    broker_utils_send_closed_resp(link, req, NULL);
    return 0;
}
