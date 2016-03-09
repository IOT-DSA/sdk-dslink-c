//
// Created by rinick on 09/03/16.
//

#include <broker/sys/token.h>
#include "broker/msg/msg_invoke.h"

static
int load_tokens(BrokerNode *tokenRootNode){
    (void) tokenRootNode;
    return 0;
}

static
void add_token_invoke(RemoteDSLink *link,
                  BrokerNode *node,
                  json_t *request) {
    (void)(link);
    (void)(node);
    (void)(request);

}

int init_tokens(BrokerNode *sysNode) {
    BrokerNode *tokensNode = broker_node_create("tokens", "node");
    if (!tokensNode) {
        return 1;
    }

    if (broker_node_add(sysNode, tokensNode) != 0) {
        broker_node_free(tokensNode);
        return 1;
    }

    BrokerNode *tokenRootNode = broker_node_create("root", "node");
    if (!tokenRootNode) {
        return 1;
    }

    if (broker_node_add(tokensNode, tokenRootNode) != 0) {
        broker_node_free(tokenRootNode);
        return 1;
    }


    BrokerNode *addTokenAction = broker_node_create("add", "node");
    if (!addTokenAction) {
        return 1;
    }

    if (json_object_set_new(addTokenAction->meta, "$invokable",
                            json_string("config")) != 0) {
        broker_node_free(addTokenAction);
        return 1;
    }


    json_error_t err;
    json_t *paramList = json_loads("[{\"name\":\"TimeRange\",\"type\":\"string\",\"editor\":\"daterange\"},{\"name\":\"Count\",\"type\":\"number\",\"description\":\"how many times this token can be used\"},{\"name\":\"Managed\",\"type\":\"bool\",\"description\":\"when a managed token is deleted, server will delete all the dslinks associated with the token\"}]",
        0, &err);
    if (!paramList || json_object_set_new(addTokenAction->meta, "$params", paramList) != 0) {
        return 1;
    }

    json_t *columnList = json_array();
    if (broker_invoke_create_param(columnList, "tokenName", "string") != 0
        || json_object_set_new(addTokenAction->meta, "$columns", columnList) != 0) {
        return 1;
    }


    if (broker_node_add(tokenRootNode, addTokenAction) != 0) {
        broker_node_free(tokenRootNode);
        return 1;
    }

    addTokenAction->on_invoke = add_token_invoke;

    return load_tokens(tokenRootNode);
}

