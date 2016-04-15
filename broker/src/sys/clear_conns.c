#include "broker/stream.h"
#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/utils.h"
#include "broker/sys/clear_conns.h"

static
void clear_conns(RemoteDSLink *link,
                 BrokerNode *node,
                 json_t *req, PermissionLevel maxPermission) {
    (void)maxPermission;
    (void)node;
    Map* map = dslink_calloc(1, sizeof(Map));

    dslink_map_init(map, dslink_map_str_cmp,
                    dslink_map_str_key_len_cal, dslink_map_hash_key);

    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp, "stream", json_string_nocheck("open"));
    json_t *updates = json_array();

    List nodeToDelete;
    list_init(&nodeToDelete);

    dslink_map_foreach(link->broker->downstream->children) {
        DownstreamNode *dsn = (DownstreamNode *) entry->value->data;
        if (dsn->link) {
            dslink_map_set(
                    map,
                    dslink_str_ref(dsn->name), dslink_ref(dsn, NULL));
        } else {
            dslink_list_insert(&nodeToDelete, dsn);
            json_t *update = json_object();
            json_object_set_new_nocheck(update, "name", json_string_nocheck(dsn->name));
            json_object_set_new_nocheck(update, "change",
                                        json_string_nocheck("remove"));
            json_array_append_new(updates, update);
        }
    }

    json_object_set_new_nocheck(resp, "updates", updates);

    if (link->broker->downstream->list_stream) {
        dslink_map_foreach(&link->broker->downstream->list_stream->requester_links) {
            uint32_t *rid = entry->value->data;
            json_object_set_new_nocheck(resp, "rid", json_integer(*rid));
            broker_ws_send_obj(entry->key->data, top);
        }
    }

    json_decref(top);

    dslink_map_clear(link->broker->downstream->children);
    Map* omap = link->broker->downstream->children;

    link->broker->downstream->children = map;

    dslink_map_free(omap);
    broker_utils_send_closed_resp(link, req, NULL);

    dslink_list_foreach(&nodeToDelete) {
        ListNode *lnode =  (ListNode *)node;
        DownstreamNode *dsn = lnode->value;
        // set to NULL to skip the removing from parent part
        dsn->parent = NULL;
        broker_node_free((BrokerNode*)dsn);
    }
    broker_downstream_nodes_changed(mainLoop->data);
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
                            json_string_nocheck("write")) != 0) {
        return 1;
    }

    if (json_object_set_new(clearConnsNode->meta, "$name",
                            json_string_nocheck("Clear Conns")) != 0) {
        return 1;
    }

    clearConnsNode->on_invoke = clear_conns;

    return 0;
}
