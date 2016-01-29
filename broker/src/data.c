#include <dslink/utils.h>
#include <dslink/err.h>

#include "broker/config.h"
#include "broker/broker.h"

static
int broker_data_add_meta(BrokerNode *node, const char *name, json_t *value) {
    if (!value) {
        return 1;
    }
    name = dslink_strdup(name);
    if (!name) {
        return DSLINK_ALLOC_ERR;
    }
    int ret = 0;
    if ((ret = dslink_map_set(node->meta, (void *) name,
                              (void **) &value)) != 0) {
        free((void *) name);
    }
    return ret;
}

static
int broker_data_safe_json_set(json_t *obj, const char *name, json_t *data) {
    if (!data) {
        return 1;
    }

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

    if (broker_data_add_meta(node, "$invokable",
                             json_string("$write")) != 0) {
        broker_node_free(node);
        return 1;
    }

    json_t *paramList = json_array();
    if (broker_data_create_param(paramList, "Name", "string") != 0
        || broker_data_add_meta(node, "$params", paramList) != 0) {
        goto fail;
    }

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

    if (broker_data_add_meta(node, "$invokable",
                             json_string("$write")) != 0) {
        broker_node_free(node);
        return 1;
    }

    json_t *paramList = json_array();
    char type[] = "enum[string,number,bool,array,map,dynamic]";
    char editor[] = "enum[none,textarea,password,daterange,date]";
    if (broker_data_create_param(paramList, "Name", "string") != 0
        || broker_data_create_param(paramList, "Type", type) != 0
        || broker_data_create_param(paramList, "Editor", editor) != 0
        || broker_data_add_meta(node, "$params", paramList) != 0) {
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

    if (broker_data_add_meta(node, "$invokable",
                             json_string("$write")) != 0) {
        broker_node_free(node);
        return 1;
    }

    json_t *paramList = json_array();
    if (broker_data_create_param(paramList, "Path", "string") != 0
        || broker_data_create_param(paramList, "Value", "dynamic") != 0
        || broker_data_create_param(paramList, "Timestamp", "string") != 0) {
        goto fail;
    }

    if (broker_data_add_meta(node, "$params", paramList) != 0) {
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
