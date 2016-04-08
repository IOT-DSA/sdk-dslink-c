#include <broker/node.h>
#include <broker/broker.h>
#include <broker/handshake.h>
#include <broker/utils.h>
#include <broker/data/data.h>
#include <broker/config.h>
#include <string.h>
#include <dslink/utils.h>
#include <broker/msg/msg_subscribe.h>
#include <broker/subscription.h>

static
void broker_save_downstream_virtual_nodes(VirtualDownstreamNode *node, const char *name, json_t *pdata) {
    json_t *data = json_copy(node->meta);

    json_t *plist = permission_list_save(node->permissionList);
    if (plist) {
        json_object_set_new_nocheck(data, "?permissions", plist);
    }

    dslink_map_foreach(&node->childrenNode) {
        VirtualDownstreamNode *vnode = entry->value->data;
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
            VirtualDownstreamNode *vnode = entry->value->data;
            broker_save_downstream_virtual_nodes(vnode, entry->key->data, data);
        }

        json_object_set_new_nocheck(top, node->name, data);
    }

    const char *path = broker_get_storage_path("conns.json");

    json_dump_file(top, path, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_INDENT(2));
    json_decref(top);
    dslink_free((void *) path);
}

static
void broker_load_downstream_virtual_nodes(Map *map, const char *name, json_t *data) {
    VirtualDownstreamNode *node = dslink_malloc(sizeof(VirtualDownstreamNode));
    virtual_downstream_node_init(node);
    dslink_map_set(map, dslink_str_ref(name), dslink_ref(node, NULL));
    if (json_is_object(data)) {
        const char *key;
        json_t *value;
        json_object_foreach(data, key, value) {
            if (*key == '?') {
                if (strcmp(key, "?permissions") == 0) {
                    // when loading fails, permissionList will be NULL.
                    node->permissionList = permission_list_load(value);
                }
            } else if (*key == '$' || *key == '@') {
                // copy metadata
                json_object_set_nocheck(node->meta, key, value);
            } else {
                broker_load_downstream_virtual_nodes(&node->childrenNode, key, value);
            }
        }
    }
}

int broker_load_downstream_nodes(Broker *broker) {
    BrokerNode *downstream = broker->downstream;

    const char *path = broker_get_storage_path("conns.json");

    json_error_t err;
    json_t *top = json_load_file(path, 0, &err);

    if (top) {
        const char *nodename;
        json_t *nodemap;
        json_object_foreach(top, nodename, nodemap) {
            if (*nodename == '$' || *nodename == '@') {
                // skip meta for root node
            } else if (json_is_object(nodemap)){
                if (!json_is_object(nodemap)) {
                    continue;
                }
                json_t *dsIdJson = json_object_get(nodemap, "$$dsId");
                if (!json_is_string(dsIdJson)) {
                    continue;
                }
                DownstreamNode *node = broker_init_downstream_node(downstream, nodename);
                node->dsId = dslink_str_ref(json_string_value(dsIdJson));

                const char *key;
                json_t *value;
                json_object_foreach(nodemap, key, value) {
                    if (*key == '?') {
                        if (strcmp(key, "?permissions") == 0) {
                            // when loading fails, permissionList will be NULL.
                            node->permissionList = permission_list_load(value);
                        }
                    } else if (*key == '$' || *key == '@') {
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

    dslink_free((void *) path);

    return 0;
}

void broker_data_nodes_changed(Broker *broker) {
    if (!broker) {
        // broker == NULL, during deserialization
        return;
    }
    if (!broker->saveDataHandler) {
        broker->saveDataHandler = dslink_calloc(1, sizeof(uv_timer_t));
        uv_timer_init(mainLoop, broker->saveDataHandler);
        uv_timer_start(broker->saveDataHandler, broker_save_data_nodes, 100, 0);
    }
}

static
json_t *broker_save_data_node(BrokerNode *node) {
    json_t *data = json_object();

    // save metadata
    const char *key;
    json_t *value;
    json_object_foreach(node->meta, key, value) {
        json_object_set_nocheck(data, key, value);
    }

    // save permission list
    json_t *plist = permission_list_save(node->permissionList);
    if (plist) {
        json_object_set_new_nocheck(data, "?permissions", plist);
    }

    // save children
    dslink_map_foreach(node->children) {
        BrokerNode *childNode = entry->value->data;
        // don't serialize actions
        if (!json_object_get(childNode->meta, "$invokable")) {
            json_t *childData = broker_save_data_node(childNode);
            json_object_set_new(data, entry->key->data, childData);
        }

    }

    return data;
}

void broker_save_data_nodes(uv_timer_t* handle) {
    Broker *broker = mainLoop->data;
    if (handle) {
        uv_timer_stop(handle);
        uv_close((uv_handle_t *)handle, broker_free_handle);
        broker->saveDataHandler = NULL;
    }

    json_t *top = broker_save_data_node(broker->data);

    const char *path = broker_get_storage_path("data.json");

    json_dump_file(top, path, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY | JSON_INDENT(2));
    json_decref(top);

    dslink_free((void *) path);
}

static
void broker_load_data_node(BrokerNode *node, json_t *data) {

    // save metadata
    const char *key;
    json_t *value;
    json_object_foreach(data, key, value) {
        if (*key == '?') {
            if (strcmp(key, "?permissions") == 0) {
                // when loading fails, permissionList will be NULL.
                node->permissionList = permission_list_load(value);
            }
        } if (*key == '$' || *key == '@') {
            json_object_set_nocheck(node->meta, key, value);
        } else {
            BrokerNode *child = broker_node_create(key, "node");
            json_object_set_new_nocheck(child->meta, "$type",
                                        json_string_nocheck("dynamic"));
            json_object_set_new_nocheck(child->meta, "$writable",
                                        json_string_nocheck("write"));

            broker_node_add(node, child);
            broker_create_data_actions(child);
            broker_load_data_node(child, value);
        }
    }
}

int broker_load_data_nodes(Broker *broker) {
    const char *path = broker_get_storage_path("data.json");

    json_error_t err;
    json_t *top = json_load_file(path, 0, &err);

    if (top) {
        broker_load_data_node(broker->data, top);
        json_decref(top);
    }
    return 0;
}


int broker_load_qos_storage(Broker *broker) {
    json_t *loaded = dslink_storage_traverse(broker->storage);

    const char *key;
    json_t *value;

    char *out;
    json_t *loadedCopy = json_copy(loaded);
    json_object_foreach(loadedCopy, key, value) {
        if (!json_is_object(value)) {
            continue;
        }
        char *reqPath = dslink_str_unescape(key);
        BrokerNode *node = broker_node_get(broker->root, reqPath, &out);
        if (node && node->type == DOWNSTREAM_NODE) {
            const char *key2;
            json_t *value2;
            json_object_foreach(value, key2, value2) {
                if (json_array_size(value2) != 2) {
                    continue;
                }
                json_t *qosJson = json_array_get(value2, 0);
                json_t *qosQueue = json_array_get(value2, 1);

                if (!json_is_array(qosQueue) || !json_is_integer(qosJson)) {
                    continue;
                }
                uint8_t qos = (uint8_t)json_integer_value(qosJson);

                char *resqPath = dslink_str_unescape(key2);

                SubRequester *subreq = broker_create_sub_requester((DownstreamNode*)node, resqPath, 0, qos, qosQueue);
                broker_add_new_subscription(broker, subreq);

                dslink_free(resqPath);
            }
        } else {
            dslink_storage_destroy_group(broker->storage, reqPath);
        }
        dslink_free(reqPath);
    }
    json_decref(loadedCopy);
    return 0;
}
