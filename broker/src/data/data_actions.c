#include <jansson.h>
#include "broker/msg/msg_invoke.h"

#include "broker/data/data_actions.h"

BrokerNode *broker_data_create_delete_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("deleteNode", "node");
    if (!node) {
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string_nocheck("write")) != 0
        || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return NULL;
    }

    return node;
}

BrokerNode *broker_data_create_add_node_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("addNode", "node");
    if (!node) {
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string_nocheck("write")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    json_t *paramList = json_array();
    if (broker_invoke_create_param(paramList, "Name", "string") != 0
        || json_object_set_new(node->meta, "$params", paramList) != 0
        || broker_node_add(parent, node) != 0) {
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
    if (!node) {
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string_nocheck("write")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    json_t *paramList = json_array();
    char type[] = "enum[string,number,bool,array,map,dynamic]";
    char editor[] = "enum[none,textarea,password,daterange,date]";
    if (broker_invoke_create_param(paramList, "Name", "string") != 0
        || broker_invoke_create_param(paramList, "Type", type) != 0
        || broker_invoke_create_param(paramList, "Editor", editor) != 0
        || json_object_set_new(node->meta, "$params", paramList) != 0
        || broker_node_add(parent, node) != 0) {
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
    if (!node) {
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string_nocheck("write")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    json_t *paramList = json_array();
    if (broker_invoke_create_param(paramList, "Path", "string") != 0
        || broker_invoke_create_param(paramList, "Value", "dynamic") != 0
        || broker_invoke_create_param(paramList, "Timestamp", "string") != 0
        || json_object_set_new(node->meta, "$params", paramList) != 0
        || broker_node_add(parent, node) != 0) {
        goto fail;
    }

    return node;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return NULL;
}
