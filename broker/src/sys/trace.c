#include <broker/node.h>
#include <broker/utils.h>

static
void trace_requester(RemoteDSLink *link,
                      BrokerNode *node,
                      json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    (void)node;
    broker_utils_send_closed_resp(link, req, NULL);
}

int init_trace_node(BrokerNode *sysNode) {
    BrokerNode *traceNode = broker_node_create("trace", "node");
    if (!traceNode) {
        return 1;
    }

    if (broker_node_add(sysNode, traceNode) != 0) {
        broker_node_free(traceNode);
        return 1;
    }

    BrokerNode *traceRequester = broker_node_create("traceRequester", "node");
    if (!traceRequester) {
        return 1;
    }

    if (broker_node_add(traceNode, traceRequester) != 0) {
        broker_node_free(traceRequester);
        return 1;
    }


    if (json_object_set_new(traceRequester->meta, "$invokable",
                            json_string_nocheck("config")) != 0) {
        return 1;
    }


    traceRequester->on_invoke = trace_requester;

    return 0;
}
