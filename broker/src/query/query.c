#include "broker/msg/msg_invoke.h"
#include "broker/query/query.h"

static
void query_invoke(struct RemoteDSLink *link,
                         struct BrokerNode *node,
                         json_t *request) {
    if (link && node && request){

    }
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

    node->on_invoke = query_invoke;

    return node;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return NULL;
}
