//
// Created by Kenneth Endfinger on 3/15/16.
//

#include "broker/broker.h"
#include "broker/utils.h"
#include "broker/sys/clear_conns.h"

static
void clear_conns(RemoteDSLink *link,
                 BrokerNode *node,
                 json_t *req) {
    (void)node;
    (void)req;
    Map* map = calloc(1, sizeof(Map));

    dslink_map_init(map, dslink_map_str_cmp,
                    dslink_map_str_key_len_cal, dslink_map_hash_key);

    dslink_map_foreach(link->broker->downstream->children) {
        BrokerNode *dsn = (BrokerNode *) entry->value->data;
        if (!json_object_get(dsn->meta, "$disconnectedTs")) {
            dslink_map_set(
                    map,
                    dslink_str_ref(dsn->name), dslink_ref(dsn, NULL));
        }
    }

    dslink_map_clear(link->broker->downstream->children);
    Map* omap = link->broker->downstream->children;

    link->broker->downstream->children = map;

    dslink_map_free(omap);
    broker_utils_send_closed_resp(link, req, NULL);
}

int init_clear_conns(BrokerNode *sysNode) {
    BrokerNode *clearConnsNode = broker_node_create("clearConns", "node");
    if (!clearConnsNode) {
        return 1;
    }

    if (broker_node_add(sysNode, clearConnsNode) != 0) {
        broker_node_free(clearConnsNode);
        return 1;
    }

    if (json_object_set_new(clearConnsNode->meta, "$invokable",
                            json_string("write")) != 0) {
        return 1;
    }

    if (json_object_set_new(clearConnsNode->meta, "$name",
                            json_string("Clear Conns")) != 0) {
        return 1;
    }

    clearConnsNode->on_invoke = clear_conns;

    return 0;
}
