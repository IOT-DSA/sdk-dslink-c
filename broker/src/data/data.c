#include "broker/broker.h"
#include "broker/data/data_actions.h"
#include "broker/stream.h"
#include "broker/net/ws.h"

static
int create_actions(BrokerNode *node);

static
void send_closed_resp(RemoteDSLink *link, json_t *req) {
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

static
void on_delete_node_invoked(RemoteDSLink *link,
                            BrokerNode *node, json_t *req) {
    send_closed_resp(link, req);
    node = node->parent;
    if (node->list_stream->updates_cache) {
        json_object_del(node->list_stream->updates_cache, node->name);
    }
    if (node->list_stream->clients.items <= 0) {
        return;
    }

    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp, "stream", json_string_nocheck("open"));
    json_t *updates = json_array();
    json_t *update = json_object();
    json_object_set_new_nocheck(update, "name", json_string(node->name));
    json_object_set_new_nocheck(update, "change",
                                json_string_nocheck("remove"));
    json_array_append_new(updates, update);
    json_object_set_new_nocheck(resp, "updates", updates);
    dslink_map_foreach(&node->parent->list_stream->clients) {
        uint32_t *rid = entry->key;
        json_object_set_new_nocheck(resp, "rid", json_integer(*rid));
        broker_ws_send_obj(entry->value, top);
    }

    json_decref(top);
    broker_node_free(node);
}

static
void on_add_node_invoked(RemoteDSLink *link,
                         BrokerNode *node, json_t *req) {
    send_closed_resp(link, req);

    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }

    node = node->parent;
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
    dslink_map_foreach(&node->list_stream->clients) {
        uint32_t *rid = entry->key;
        json_object_set_new_nocheck(resp, "rid", json_integer(*rid));
        broker_ws_send_obj(entry->value, top);
    }

    json_decref(top);
}

static
void on_add_value_invoked(RemoteDSLink *link,
                         BrokerNode *node, json_t *req) {
    send_closed_resp(link, req);

    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }

    node = node->parent;
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

    if (create_actions(child) != 0) {
        broker_node_free(child);
        return;
    }

    json_object_set_new_nocheck(child->meta, "$type",
                                json_string_nocheck("dynamic"));

    if (node->list_stream->clients.items <= 0) {
        return;
    }

    json_t *update = json_array();
    json_t *obj = json_object();
    json_array_append_new(update, json_string(name));
    json_array_append_new(update, obj);
    json_object_set_new_nocheck(obj, "$is", json_string("node"));
    json_object_set_new_nocheck(obj, "$type",
                                json_string_nocheck("dynamic"));
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
    dslink_map_foreach(&node->list_stream->clients) {
        uint32_t *rid = entry->key;
        json_object_set_new_nocheck(resp, "rid", json_integer(*rid));
        broker_ws_send_obj(entry->value, top);
    }

    json_decref(top);
}

static
void on_publish_invoked(RemoteDSLink *link,
                          BrokerNode *node, json_t *req) {
    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }

    const char *path = json_string_value(json_object_get(params, "Path"));
    if (!path) {
        return;
    }

    json_t *value = json_object_get(params, "Value");
    if (!value) {
        return;
    }

    char *tmp = (char *) path;
    node = broker_node_get(link->broker->root, path, (void *) &tmp);
    if (!(node && node->type == REGULAR_NODE)) {
        return;
    }

    json_incref(value);
    if (node->value) {
        json_decref(node->value);
    }
    node->value = value;

    // TODO: store the RID
    // TODO: notify query handlers
}

static
int create_actions(BrokerNode *node) {
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

    return 0;
}
