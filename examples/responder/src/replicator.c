#define LOG_TAG "replicator"

#include <dslink/log.h>
#include <dslink/ws.h>
#include "replicator.h"

#define NODE_COUNT 5

static
void delete_nodes(DSLink *link, DSNode *node,
                  json_t *rid, json_t *params) {
    (void) params;
    json_t *top = json_object();
    if (!top) {
        return;
    }
    json_t *resps = json_array();
    if (!resps) {
        json_delete(top);
        return;
    }
    json_object_set_new_nocheck(top, "responses", resps);

    json_t *resp = json_object();
    if (!resp) {
        json_delete(top);
        return;
    }
    json_array_append_new(resps, resp);

    json_object_set_nocheck(resp, "rid", rid);
    json_object_set_new_nocheck(resp, "stream", json_string("closed"));
    dslink_ws_send_obj(link->_ws, top);
    json_delete(top);

    node = node->parent;
    for (int i = 0; i < NODE_COUNT; ++i) {
        char buf[10];
        snprintf(buf, sizeof(buf), "%d", i);

        DSNode *n = dslink_map_get(node->children, buf);
        if (n) {
            dslink_node_tree_free(link, n);
        }
    }
}

static
void create_node(void *data, EventLoop *loop) {
    DSLink *link = ((void **) data)[0];
    DSNode *parent = ((void **) data)[1];
    int *num = ((void **) data)[2];
    if (!dslink_map_contains(link->responder->list_subs,
                             (void *) parent->path)) {
        free(num);
        free(data);
        return;
    }

    char buf[10];
    snprintf(buf, sizeof(buf), "%d", *num);

    DSNode *child = dslink_node_create(parent, buf, "node");
    if (!child) {
        free(num);
        free(data);
        return;
    }
    dslink_node_add_child(link, child);

    if (++(*num) < NODE_COUNT) {
        dslink_event_loop_schedd(loop, create_node, data, 1000);
    } else {
        free(num);
        free(data);
    }
}

static
void list_opened(DSLink *link, DSNode *node) {
    (void) link;
    log_info("List opened for: %s\n", node->path);

    int *pos = malloc(sizeof(int));
    if (!pos) {
        return;
    }
    void **a = malloc(sizeof(void *) * 3);
    if (!a) {
        free(pos);
        return;
    }
    *pos = 0;
    a[0] = link;
    a[1] = node;
    a[2] = pos;
    dslink_event_loop_schedd(&link->loop, create_node, a, 1000);
}

static
void list_closed(DSLink *link, DSNode *node) {
    (void) link;
    log_info("List closed for: %s\n", node->path);
}

void responder_init_replicator(DSLink *link, DSNode *root) {
    DSNode *rep = dslink_node_create(root, "replicator", "node");
    if (!rep) {
        log_warn("Failed to create the replicator node\n");
        return;
    }

    rep->on_list_open = list_opened;
    rep->on_list_close = list_closed;

    if (dslink_node_add_child(link, rep) != 0) {
        log_warn("Failed to add the replicator node to the root\n");
        dslink_node_tree_free(link, rep);
        return;
    }

    DSNode *reset = dslink_node_create(rep, "reset", "node");
    if (!reset) {
        log_warn("Failed to create reset action node\n");
        return;
    }

    reset->on_invocation = delete_nodes;
    dslink_node_set_meta(reset, "$name", json_string("Reset"));
    dslink_node_set_meta(reset, "$invokable", json_string("read"));

    if (dslink_node_add_child(link, reset) != 0) {
        log_warn("Failed to add reset action to the replicator node\n");
        dslink_node_tree_free(link, reset);
        return;
    }
}
