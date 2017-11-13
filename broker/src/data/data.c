#include "broker/data/data.h"

#include <stdlib.h>
#include <dslink/utils.h>
#include <string.h>
#include <uv.h>
#include "broker/msg/msg_subscribe.h"
#include "broker/utils.h"
#include "broker/msg/msg_list.h"
#include "broker/broker.h"
#include "broker/data/data_actions.h"
#include "broker/net/ws.h"
#include "broker/subscription.h"

void broker_data_node_update(BrokerNode *node,
                             json_t *value,
                             uint8_t isNewValue) {
    broker_node_update_value(node, value, isNewValue);

    uv_fs_t dir;
    uv_fs_mkdir(NULL, &dir, "data", 0770, NULL);

    char *replaced = dslink_str_escape(node->path);
    if (!replaced) {
        goto exit;
    }

    char tmp[512];
    int len = snprintf(tmp, sizeof(tmp) - 1, "data/%s", replaced);
    tmp[len] = '\0';

    json_dump_file(value, tmp, JSON_PRESERVE_ORDER | JSON_ENCODE_ANY);
exit:
    DSLINK_CHECKED_EXEC(dslink_free, replaced);
}

static
void on_delete_node_invoked(RemoteDSLink *link,
                            BrokerNode *node, json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    broker_utils_send_closed_resp(link, req, NULL);
    node = node->parent;
    if (node->list_stream) {
        if (node->list_stream->updates_cache) {
            json_object_del(node->list_stream->updates_cache, node->name);
        }
        if (node->list_stream->requester_links.size > 0) {
            json_t *top = json_object();
            json_t *resps = json_array();
            json_object_set_new_nocheck(top, "responses", resps);
            json_t *resp = json_object();
            json_array_append_new(resps, resp);
            json_object_set_new_nocheck(resp, "stream", json_string_nocheck("open"));
            json_t *updates = json_array();
            json_t *update = json_object();
            json_object_set_new_nocheck(update, "name", json_string_nocheck(node->name));
            json_object_set_new_nocheck(update, "change",
                                        json_string_nocheck("remove"));
            json_array_append_new(updates, update);
            json_object_set_new_nocheck(resp, "updates", updates);
            dslink_map_foreach(&node->parent->list_stream->requester_links) {
                uint32_t *rid = entry->value->data;
                json_object_set_new_nocheck(resp, "rid", json_integer(*rid));
                broker_ws_send_obj(entry->key->data, top);
            }
            json_decref(top);
        }
    }

    char *replaced = dslink_str_escape(node->path);
    if (replaced) {
        char tmp[256];
        int len = snprintf(tmp, sizeof(tmp) - 1, "data/%s", replaced);
        tmp[len] = '\0';

        remove(tmp);
        dslink_free(replaced);
    }


    broker_node_free(node);
    broker_data_nodes_changed(link->broker);
}

static
void handle_pending_sub(Broker *broker, BrokerNode *n) {
    if (!broker) {
        return;
    }
    ref_t *ref = dslink_map_remove_get(&broker->local_pending_sub,
                                       (char *) n->path);
    if (ref) {
        List *subs = ref->data;

        dslink_list_foreach(subs) {
            SubRequester *sub = ((ListNode *) node)->value;
            broker_handle_local_subscribe(n, sub);
        }

        dslink_decref(ref);
    }
}

static
void on_add_node_invoked(RemoteDSLink *link,
                         BrokerNode *node, json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    broker_utils_send_closed_resp(link, req, NULL);

    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }

    node = node->parent;
    const char *name = json_string_value(json_object_get(params, "Name"));
    if (!name || dslink_map_contains(node->children, (void *) name)) {
        return;
    }

    BrokerNode *child = broker_node_create(name, "node");
    if (!child) {
        return;
    }

    json_object_set_new_nocheck(child->meta, "$type",
                                json_string_nocheck("dynamic"));
    json_object_set_new_nocheck(child->meta, "$writable",
                                json_string_nocheck("write"));

    if (broker_node_add(node, child) != 0) {
        broker_node_free(child);
        return;
    }
    broker_create_data_actions(child);
    handle_pending_sub(link->broker, child);
    broker_data_nodes_changed(link->broker);
}

static
void on_add_value_invoked(RemoteDSLink *link,
                          BrokerNode *node, json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    broker_utils_send_closed_resp(link, req, NULL);

    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }

    node = node->parent;
    const char *name = json_string_value(json_object_get(params, "Name"));
    if (!name || dslink_map_contains(node->children, (void *) name)) {
        return;
    }

    BrokerNode *child = broker_node_create(name, "node");
    json_object_set_new_nocheck(child->meta, "$type",
                                json_string_nocheck("dynamic"));
    json_object_set_new_nocheck(child->meta, "$writable",
                                json_string_nocheck("write"));

    if (broker_node_add(node, child) != 0) {
        broker_node_free(child);
        return;
    }

    if (broker_create_data_actions(child) != 0) {
        broker_node_free(child);
        return;
    }
    handle_pending_sub(link->broker, child);
    broker_data_nodes_changed(link->broker);
}

void broker_create_dynamic_data_node(Broker *broker, BrokerNode *node,
                                     const char *path, json_t *value,
                                     uint8_t serialize) {
    if (*path == '/') {
        path++;
    }

    if (*path == '\0') {
        if (serialize) {
            broker_data_node_update(node, value, 0);
        } else {
            broker_node_update_value(node, value, 0);
        }

    } else {
        const char *name = strchr(path, '/');
        if (!name) {
            name = path + strlen(path);
        }

        BrokerNode *child = NULL;
        if (node->children) {
            ref_t *r = dslink_map_getl(node->children, (char *) path,
                                       name - path);
            if (r) {
                child = r->data;
            }
        }

        if (child) {
            broker_create_dynamic_data_node(broker, child, name,
                                            value, serialize);
            return;
        }

        child = broker_node_createl(path, name - path,
                                    "node", sizeof("node") - 1);
        if (!child) {
            return;
        }

        json_object_set_new_nocheck(child->meta, "$type",
                                    json_string_nocheck("dynamic"));
        json_object_set_new_nocheck(child->meta, "$writable",
                                    json_string_nocheck("write"));

        if (broker_node_add(node, child) != 0) {
            broker_node_free(child);
            return;
        }
        handle_pending_sub(broker, node);
        broker_create_data_actions(child);

        broker_create_dynamic_data_node(broker, child, name,
                                        value, serialize);
        broker_data_nodes_changed(broker);
    }
}

static
void on_publish_continuous_invoked(RemoteDSLink *link, json_t *params) {
    if (!json_is_object(params)) {
        return;
    }

    const char *path = json_string_value(json_object_get(params, "Path"));
    json_t *value = json_object_get(params, "Value");
    if (!(path && value)) {
        return;
    }

    char *tmp = (char *) path;
    BrokerNode *node = broker_node_get(link->broker->root, path,
                                       (void *) &tmp);
    if (node && node->type == REGULAR_NODE) {
        broker_node_update_value(node, value, 0);
    } else if (!node && dslink_str_starts_with(path, "/data")) {
        broker_create_dynamic_data_node(link->broker, link->broker->root,
                                        path, value, 0);
    }
}

static
void on_publish_invoked(RemoteDSLink *link,
                        BrokerNode *node, json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    (void) node;
    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }
    on_publish_continuous_invoked(link, params);
    uint32_t rid = (uint32_t) json_integer_value(json_object_get(req, "rid"));
    BrokerInvokeStream *s = broker_stream_invoke_init();
    s->continuous_invoke = on_publish_continuous_invoked;

    s->requester = link;
    s->requester_rid = rid;
    dslink_map_set(&link->requester_streams, dslink_int_ref(rid),
                   dslink_ref(s, NULL));
}

int broker_create_data_actions(BrokerNode *node) {
    BrokerNode *addNode = broker_data_create_add_node_action(node);
    BrokerNode *addValue = broker_data_create_add_value_action(node);
    BrokerNode *deleteNode = broker_data_create_delete_action(node);
    if (!(addNode && addValue && deleteNode)) {
        broker_node_free(addNode);
        broker_node_free(addValue);
        broker_node_free(deleteNode);
        return 1;
    }

    addNode->on_invoke = on_add_node_invoked;
    addValue->on_invoke = on_add_value_invoked;
    deleteNode->on_invoke = on_delete_node_invoked;
    return 0;
}

static
void deserialize_data_node_values(BrokerNode *root) {
    uv_fs_t dir;
    if (uv_fs_scandir(NULL, &dir, "data", 0, NULL) < 0) {
        return;
    }

    uv_dirent_t d;
    while (uv_fs_scandir_next(&dir, &d) != UV_EOF) {
        if (d.type != UV_DIRENT_FILE) {
            continue;
        }

        char *path = dslink_str_unescape(d.name);
        if (!path) {
            continue;
        }

        char tmp[256];
        int len = snprintf(tmp, sizeof(tmp) - 1, "data/%s", d.name);
        tmp[len] = '\0';

        json_error_t err;
        json_t *val = json_load_file(tmp, JSON_PRESERVE_ORDER | JSON_DECODE_ANY, &err);
        if (val) {
            broker_create_dynamic_data_node(NULL, root, path, val, 0);
        }

        dslink_free(path);
    }
}

int broker_data_node_populate(BrokerNode *dataNode) {
    if (!dataNode) {
        return 1;
    }

    BrokerNode *addNode = broker_data_create_add_node_action(dataNode);
    BrokerNode *addValue = broker_data_create_add_value_action(dataNode);
    BrokerNode *publish = broker_data_create_publish_action(dataNode);
    if (!(addNode && addValue && publish)) {
        broker_node_free(dataNode);
        return 1;
    }

    addNode->on_invoke = on_add_node_invoked;
    addValue->on_invoke = on_add_value_invoked;
    publish->on_invoke = on_publish_invoked;
    deserialize_data_node_values(dataNode->parent);

    return 0;
}
