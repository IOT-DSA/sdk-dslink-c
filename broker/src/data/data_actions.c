#include <jansson.h>

#include "broker/data/data_actions.h"

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

BrokerNode *broker_data_create_delete_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("deleteNode", "node");
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string("write")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    return node;
}

BrokerNode *broker_data_create_add_node_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("addNode", "node");
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string("write")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    json_t *paramList = json_array();
    if (broker_data_create_param(paramList, "Name", "string") != 0
        || json_object_set_new(node->meta, "$params", paramList) != 0) {
        goto fail;
    }

    return node;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return NULL;
}

BrokerNode *broker_data_create_add_value_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("addValue", "node");
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string("write")) != 0) {
        broker_node_free(node);
        return NULL;
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

    return node;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return NULL;
}

BrokerNode *broker_data_create_publish_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("publish", "node");
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string("write")) != 0) {
        broker_node_free(node);
        return NULL;
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
    return node;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return NULL;
}
