#define LOG_TAG "replicator"

#include <dslink/log.h>
#include "replicator.h"

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
    dslink_node_add_child(link, parent, child);

    if (++(*num) < 10) {
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

    if (dslink_node_add_child(link, root, rep) != 0) {
        log_warn("Failed to add the replicator node to the root\n");
        dslink_node_tree_free(rep);
        return;
    }
}
