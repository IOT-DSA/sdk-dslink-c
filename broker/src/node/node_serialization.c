#include "broker/node.h"


#include <broker/broker.h>
#include <broker/handshake.h>
#include <string.h>
#include <broker/utils.h>

static
void broker_save_downstream_virtual_nodes(VirtualPermissionNode *node, const char *name, json_t *pdata) {
    json_t *data = json_object();

    json_t *plist = permission_list_save(node->permissionList);
    if (plist) {
        json_object_set_new_nocheck(data, "?permissions", plist);
    }
    dslink_map_foreach(&node->childrenNode) {
        VirtualPermissionNode *vnode = entry->value->data;
        broker_save_downstream_virtual_nodes(vnode, entry->key->data, data);
    }
    json_object_set_new_nocheck(pdata, name, data);
}

void broker_downstream_nodes_changed(Broker *broker) {
    if (!broker->saveConnsHandler) {
        broker->saveConnsHandler = dslink_calloc(1, sizeof(uv_timer_t));
        uv_timer_init(mainLoop, broker->saveConnsHandler);
        uv_timer_start(broker->saveConnsHandler, broker_save_downstream_nodes, 100, 0);
    }
}
void broker_save_downstream_nodes(uv_timer_t *handle) {
    Broker *broker = mainLoop->data;
    if (handle) {
        uv_timer_stop(handle);
        uv_close((uv_handle_t *)handle, broker_free_handle);
        broker->saveConnsHandler = NULL;
    }

    json_t *top = json_object();

    dslink_map_foreach(broker->downstream->children) {
        DownstreamNode *node = entry->value->data;
        json_t *data = json_copy(node->meta);

        json_t *plist = permission_list_save(node->permissionList);
        if (plist) {
            json_object_set_new_nocheck(data, "?permissions", plist);
        }
        dslink_map_foreach(&node->children_permissions) {
            VirtualPermissionNode *vnode = entry->value->data;
            broker_save_downstream_virtual_nodes(vnode, entry->key->data, data);
        }

        json_object_set_new_nocheck(top, node->name, data);
    }

    char path[512];

    int len = snprintf(path, sizeof(path) - 1, "conns.json");
    path[len] = '\0';

    json_dump_file(top, path, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_INDENT(2));
    json_decref(top);
}


static
void broker_load_downstream_virtual_nodes(Map *map, const char *name, json_t *data) {
    VirtualPermissionNode *node = dslink_malloc(sizeof(VirtualPermissionNode));
    virtual_permission_init(node);
    dslink_map_set(map, dslink_str_ref(name), dslink_ref(node, NULL));
    if (json_is_object(data)) {
        const char *key;
        json_t *value;
        json_object_foreach(data, key, value) {
            if (*key == '?') {
                if (strcmp(key, "?permissions")) {
                    // when loading fails, permissionList will be NULL.
                    node->permissionList = permission_list_load(value);
                }
            } if (*key == '$' || *key == '@') {
                // TODO copy attributes?
            } else {
                broker_load_downstream_virtual_nodes(&node->childrenNode, key, value);
            }
        }
    }
}

void broker_load_downstream_nodes(Broker *broker) {
    BrokerNode *downstream = broker->downstream;

    char path[512];

    int len = snprintf(path, sizeof(path) - 1, "conns.json");
    path[len] = '\0';

    json_error_t err;
    json_t *top = json_load_file(path, 0, &err);

    if (top) {
        const char *nodename;
        json_t *nodemap;
        json_object_foreach(top, nodename, nodemap) {
            if (*nodename == '$' || *nodename == '@') {
                // skip meta for root node
            } else if (json_is_object(nodemap)){
                DownstreamNode *node = broker_init_downstream_node(downstream, nodename);

                const char *key;
                json_t *value;
                json_object_foreach(nodemap, key, value) {
                    if (*key == '$' || *key == '@') {
                        // copy metadata
                        json_object_set_nocheck(node->meta, key, value);
                    } else {
                        broker_load_downstream_virtual_nodes(&node->children_permissions, key, value);
                    }
                }
            }
        }
        json_decref(top);
    }
}

void broker_data_nodes_changed(Broker *broker) {
    if (!broker->saveDataHandler) {
        broker->saveDataHandler = dslink_calloc(1, sizeof(uv_timer_t));
        uv_timer_init(mainLoop, broker->saveDataHandler);
        uv_timer_start(broker->saveDataHandler, broker_save_downstream_nodes, 100, 0);
    }
}

void broker_save_data_nodes(uv_timer_t* handle) {
    Broker *broker = mainLoop->data;
    if (handle) {
        uv_timer_stop(handle);
        uv_close((uv_handle_t *)handle, broker_free_handle);
        broker->saveDataHandler = NULL;
    }
}

void broker_load_data_nodes(Broker *broker) {
    (void)broker;
}
