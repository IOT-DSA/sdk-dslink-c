#include <string.h>
#include "broker/msg/msg_invoke.h"
#include "broker/query/query.h"

static
void query_invoke(RemoteDSLink *link,
                  BrokerNode *node,
                  json_t *req) {
    if (!(link && node && req)) {
        return;
    }

    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        return;
    }

    const char *query = json_string_value(json_object_get(params, "query"));
    if (!query) {
        return;
    }

    const char *pos = strchr(query, ' ');
    if (!(pos && strncmp(query, "list", pos - query) == 0)) {
        return;
    }

    query = ++pos;
    const char *path = query;
    size_t pathLen = 0;
    pos = strchr(query, '|');
    if (!pos) {
        return;
    }
    pathLen = pos - query;

    // Assume the user wants to subscribe for now
}

BrokerNode *broker_query_create_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("query", "node");
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string("write")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$result",
                            json_string("stream")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    json_t *paramList = json_array();
    if (broker_invoke_create_param(paramList, "query", "string") != 0
        || json_object_set_new(node->meta, "$params", paramList) != 0) {
        goto fail;
    }

    json_t *columnList = json_array();
    if (broker_invoke_create_param(columnList, "path", "string") != 0
        || broker_invoke_create_param(columnList, "change", "string") != 0
        || broker_invoke_create_param(columnList, "value", "dynamic") != 0
        || broker_invoke_create_param(columnList, "ts", "string") != 0
        || json_object_set_new(node->meta, "$columns", columnList) != 0) {
        goto fail;
    }

    node->on_invoke = query_invoke;

    return node;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return NULL;
}
