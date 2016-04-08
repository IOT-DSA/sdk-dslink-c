#include <dslink/utils.h>
#include <broker/utils.h>
#include <string.h>
#include <broker/msg/msg_list.h>
#include "broker/data/data.h"
#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/msg/msg_set.h"


static
int broker_msg_check_set_arrtribtues(RemoteDSLink *link, json_t *req, const char *path) {
    const char * name = strrchr(path, '/') + 1;
    if (*name == '$') {
        // set config, not implemented
        broker_utils_send_closed_resp(link, req, "invalidParameter");
        return 1;
    }
    if (*name != '@') {
        // not attribute
        return 0;
    }
    json_t *value = json_object_get(req, "value");
    if (!value) {
        broker_utils_send_closed_resp(link, req, "invalidParameter");
        return 1;
    }

    char *nodePath = dslink_strdupl(path, name-path-1);

    char *out = NULL;
    BrokerNode *node = broker_node_get(link->broker->root, nodePath, &out);

    {
        json_t *maxPermitJson = json_object_get(req, "permit");
        PermissionLevel maxPermit = PERMISSION_CONFIG;
        if (json_is_string(maxPermitJson)) {
            maxPermit = permission_str_level(json_string_value(maxPermitJson));
        }

        PermissionLevel permissionOnPath = get_permission(nodePath, link->broker->root, link);
        if (permissionOnPath > maxPermit) {
            permissionOnPath = maxPermit;
        }

        if (permissionOnPath < PERMISSION_WRITE) {
            broker_utils_send_closed_resp(link, req, "permissionDenied");
            return 0;
        }
    }

    if (node && node->type == DOWNSTREAM_NODE) {
        if (set_downstream_attribute(out + 1, (DownstreamNode*)node, name, value)) {
            ref_t *ref = dslink_map_get(&((DownstreamNode*)node)->list_streams, out);
            if (ref) {
                BrokerListStream *liststream = ref->data;
                update_list_attribute(node, liststream, name, value);
            }
            broker_downstream_nodes_changed(link->broker);
        }
    } else if (node) {
        json_object_set_nocheck(node->meta, name, value);
        if (node->list_stream) {
            update_list_attribute(node, node->list_stream, name, value);
        }
        if (dslink_str_starts_with(path, "/data")) {
            broker_data_nodes_changed(link->broker);
        }
    }

    dslink_free(nodePath);
    broker_utils_send_closed_resp(link, req, NULL);
    return 1;
}
int broker_msg_handle_set(RemoteDSLink *link, json_t *req) {
    const char *path = json_string_value(json_object_get(req, "path"));
    json_t *rid = json_object_get(req, "rid");
    if (!(path && rid)) {
        return 1;
    }

    if (broker_msg_check_set_arrtribtues(link, req, path)) {
        // attribute set
        return 0;
    }

    // value set

    char *out = NULL;
    BrokerNode *node = broker_node_get(link->broker->root, path, &out);

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
        uint32_t reqRid = (uint32_t) json_integer_value(rid);
        if (out == NULL) {
            out = "/";
        }

        DownstreamNode *dsn = (DownstreamNode *) node;
        json_t *top = json_object();
        json_t *reqs = json_array();
        json_object_set_new_nocheck(top, "requests", reqs);
        json_object_set_new_nocheck(req, "rid", json_integer(reqRid));
        json_object_set_new_nocheck(req, "path", json_string_nocheck(out));
        json_array_append(reqs, req);

        broker_ws_send_obj(dsn->link, top);
        json_decref(top);
    } else if (node) {
        json_t *value = json_object_get(req, "value");
        if (dslink_str_starts_with(path, "/data")) {
            broker_data_node_update(node, value, 0);
        } else {
            broker_node_update_value(node, value, 0);
        }
    } else if (dslink_str_starts_with(path, "/data")) {
        json_t *value = json_object_get(req, "value");
        broker_create_dynamic_data_node(link->broker, link->broker->root, path, value, 1);
    }

    broker_utils_send_closed_resp(link, req, NULL);

    return 0;
}
