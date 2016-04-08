#include <broker/utils.h>
#include <broker/sys/sys.h>
#include <broker/broker.h>

static
void restart_broker(RemoteDSLink *link,
                     BrokerNode *node,
                     json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    (void)node;
    broker_utils_send_closed_resp(link, req, NULL);

    broker_stop(link->broker);
    exit(25);
}

int init_restart(BrokerNode *sysNode) {
    BrokerNode *restartNode = broker_node_create("restart_server", "node");
    if (!restartNode) {
        return 1;
    }

    if (broker_node_add(sysNode, restartNode) != 0) {
        broker_node_free(restartNode);
        return 1;
    }

    if (json_object_set_new(restartNode->meta, "$invokable",
                            json_string_nocheck("write")) != 0) {
        return 1;
    }

    if (json_object_set_new(restartNode->meta, "$name",
                            json_string_nocheck("Restart Broker")) != 0) {
        return 1;
    }

    restartNode->on_invoke = restart_broker;

    return 0;
}
