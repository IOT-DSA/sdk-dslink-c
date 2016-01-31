#include <broker/stream.h>
#include "broker/net/ws.h"
#include "broker/broker.h"

static
void on_add_node_invoked(RemoteDSLink *link,
                         BrokerNode *node, json_t *req) {
    {
        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_t *resp = json_object();
        json_array_append_new(resps, resp);

        json_t *rid = json_object_get(req, "rid");
        json_object_set(resp, "rid", rid);
        json_object_set_new_nocheck(resp, "stream",
                                    json_string_nocheck("closed"));

        broker_ws_send_obj(link, top);
        json_decref(top);
    }

    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }

    const char *name = json_string_value(json_object_get(params, "Name"));
    if (!name || dslink_map_contains(node->children, (void *) name)) {
        return;
    }

    // TODO: error handling
    BrokerNode *child = broker_node_create(name, "node");
    if (broker_node_add(node, child) != 0) {
        broker_node_free(child);
        return;
    }

    if (node->list_stream->clients.items <= 0) {
        return;
    }

    json_t *update = json_array();
    json_t *obj = json_object();
    json_array_append_new(update, json_string(name));
    json_array_append_new(update, obj);
    json_object_set_new_nocheck(obj, "$is", json_string("node"));
    if (node->list_stream->updates_cache) {
        json_object_set_new_nocheck(node->list_stream->updates_cache,
                                    name, update);
    }

    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp, "stream", json_string_nocheck("open"));
    json_t *updates = json_array();
    if (node->list_stream->updates_cache) {
        json_array_append(updates, update);
    } else {
        json_array_append_new(updates, update);
    }
    json_object_set_new_nocheck(resp, "updates", updates);
    {
        dslink_map_foreach(&node->list_stream->clients) {
            uint32_t *rid = entry->key;
            json_object_set_new_nocheck(resp, "rid", json_integer(*rid));
            broker_ws_send_obj(entry->value, top);
        }
    }

    json_decref(top);
}

static
int broker_data_safe_json_set(json_t *obj, const char *name, json_t *data) {
    if (json_object_set_new(obj, name, data) != 0) {
        json_decref(data);
        return 1;
    }
    return 0;
}

static
int broker_data_create_param(json_t *params,
                             const char *name, const char *type) {
    json_t *param = json_object();
    if (broker_data_safe_json_set(param, "name", json_string(name)) != 0
        || broker_data_safe_json_set(param, "type", json_string(type)) != 0
        || json_array_append_new(params, param) != 0) {
        json_decref(param);
        return 1;
    }
    return 0;
}

static
int broker_data_create_add_node_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("addNode", "node");
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return 1;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string("write")) != 0) {
        broker_node_free(node);
        return 1;
    }

    json_t *paramList = json_array();
    if (broker_data_create_param(paramList, "Name", "string") != 0
        || json_object_set_new(node->meta, "$params", paramList) != 0) {
        goto fail;
    }

    node->on_invoke = on_add_node_invoked;
    return 0;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return 1;
}

static
int broker_data_create_add_value_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("addValue", "node");
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return 1;
    }

    if (json_object_set_new(node->meta, "$invokable",
                             json_string("write")) != 0) {
        broker_node_free(node);
        return 1;
    }

    json_t *paramList = json_array();
    char type[] = "enum[string,number,bool,array,map,dynamic]";
    char editor[] = "enum[none,textarea,password,daterange,date]";
    if (broker_data_create_param(paramList, "Name", "string") != 0
        || broker_data_create_param(paramList, "Type", type) != 0
        || broker_data_create_param(paramList, "Editor", editor) != 0
        || json_object_set_new(node->meta, "$params", paramList) != 0) {
        goto fail;
    }

    return 0;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return 1;
}

static
int broker_data_create_publish_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("publish", "node");
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return 1;
    }

    if (json_object_set_new(node->meta, "$invokable",
                             json_string("write")) != 0) {
        broker_node_free(node);
        return 1;
    }

    json_t *paramList = json_array();
    if (broker_data_create_param(paramList, "Path", "string") != 0
        || broker_data_create_param(paramList, "Value", "dynamic") != 0
        || broker_data_create_param(paramList, "Timestamp", "string") != 0) {
        goto fail;
    }

    if (json_object_set_new(node->meta, "$params", paramList) != 0) {
        goto fail;
    }
    return 0;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return 1;
}

int broker_data_node_populate(BrokerNode *dataNode) {
    if (!dataNode) {
        return 1;
    }

    if (broker_data_create_add_node_action(dataNode) != 0
        || broker_data_create_add_value_action(dataNode) != 0
        || broker_data_create_publish_action(dataNode) != 0) {
        broker_node_free(dataNode);
        return 1;
    }
    return 0;
}
