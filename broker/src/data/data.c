#include <stdlib.h>
#include <dslink/mem/mem.h>
#include "broker/msg/msg_list.h"
#include "broker/broker.h"
#include "broker/data/data_actions.h"
#include "broker/net/ws.h"

static
int create_actions(BrokerNode *node);

void broker_data_send_closed_resp(RemoteDSLink *link, json_t *req) {
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
    broker_data_send_closed_resp(link, req);
    node = node->parent;
    if (node->list_stream->updates_cache) {
        json_object_del(node->list_stream->updates_cache, node->name);
    }
    if (node->list_stream->requester_links.size <= 0) {
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
    dslink_map_foreach(&node->parent->list_stream->requester_links) {
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
    broker_data_send_closed_resp(link, req);

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

    json_object_set_new_nocheck(child->meta, "$type",
                                json_string_nocheck("dynamic"));

    broker_node_update_child(node, name);
}

static
void on_add_value_invoked(RemoteDSLink *link,
                         BrokerNode *node, json_t *req) {
    broker_data_send_closed_resp(link, req);

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

    broker_node_update_child(node, name);

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
    if (!(node && node->type == REGULAR_NODE)) {
        return;
    }
    broker_node_update_value(node, value, 0);
}

static
void on_publish_invoked(RemoteDSLink *link,
                        BrokerNode *node, json_t *req) {
    (void) node;
    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }
    on_publish_continuous_invoked(link, params);
    uint32_t rid = (uint32_t) json_integer_value(json_object_get(req, "rid"));
    BrokerInvokeStream *s = broker_stream_invoke_init();
    s->continuous_invoke = on_publish_continuous_invoked;

    uint32_t *r = dslink_malloc(sizeof(uint32_t));
    *r = rid;
    dslink_map_set(&link->requester_streams, r, (void **) &s);
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
