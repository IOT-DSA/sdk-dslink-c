#define LOG_TAG "rng"

#include <dslink/log.h>
#include "rng.h"

static
void gen_number(void *data, EventLoop *loop) {
    DSLink *link = ((void **) data)[0];
    DSNode *node = ((void **) data)[1];
    if (!dslink_map_contains(link->responder->value_path_subs,
                             (void *) node->path)) {
        free(data);
        return;
    }

    int x = rand();
    dslink_node_set_value(link, node, json_integer(x));
    dslink_event_loop_schedd(loop, gen_number, data, 1000);
}

static
void responder_rng_subbed(DSLink *link, DSNode *node) {
    log_info("Subscribed to %s\n", node->path);

    void **a = malloc(sizeof(void *) * 2);
    a[0] = link;
    a[1] = node;
    dslink_event_loop_schedd(&link->loop, gen_number, a, 1000);
}

static
void responder_rng_unsubbed(DSLink *link, DSNode *node) {
    (void) link;
    log_info("Unsubscribed to %s\n", node->path);
}

void responder_init_rng(DSLink *link, DSNode *root) {
    DSNode *num = dslink_node_create(root, "rng", "node");
    if (!num) {
        log_warn("Failed to create the rng node\n");
        return;
    }

    num->on_subscribe = responder_rng_subbed;
    num->on_unsubscribe = responder_rng_unsubbed;
    if (dslink_node_set_meta(num, "$type", json_string("number")) != 0) {
        log_warn("Failed to set the type on the rng\n");
        dslink_node_tree_free(link, num);
        return;
    }

    if (dslink_node_set_value(link, num, json_integer(0)) != 0) {
        log_warn("Failed to set the value on the rng\n");
        dslink_node_tree_free(link, num);
        return;
    }

    if (dslink_node_add_child(link, root, num) != 0) {
        log_warn("Failed to add the rng node to the root\n");
        dslink_node_tree_free(link, num);
    }
}
