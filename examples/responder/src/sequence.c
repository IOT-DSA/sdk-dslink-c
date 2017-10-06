#define LOG_TAG "series"

#include <dslink/log.h>
#include "sequence.h"

int count = 0;

static
void gen_number(uv_timer_t *timer) {
    void **data = timer->data;
    DSLink *link = data[0];
    DSNode *node = data[1];

    if (!dslink_map_contains(link->responder->value_path_subs,
                             (void *) node->path)) {
        dslink_free(data);
        uv_timer_stop(timer);
        return;
    }

    ++count;
    dslink_node_update_value_new(link, node, json_real(count));
}

static
void responder_sequence_subbed(DSLink *link, DSNode *node) {
    log_info("Subscribed to %s\n", node->path);

    void **a = malloc(sizeof(void *) * 2);
    a[0] = link;
    a[1] = node;

    uv_timer_t *timer = malloc(sizeof(uv_timer_t));
    uv_timer_init(&link->loop, timer);
    timer->data = a;
    uv_timer_start(timer, gen_number, 0, 500);
}

static
void responder_sequence_unsubbed(DSLink *link, DSNode *node) {
    (void) link;
    log_info("Unsubscribed to %s\n", node->path);
}

void responder_init_sequence(DSLink *link, DSNode *root) {
    DSNode *num = dslink_node_create(root, "sequence", "node");
    if (!num) {
        log_warn("Failed to create the sequence node\n");
        return;
    }

    num->on_subscribe = responder_sequence_subbed;
    num->on_unsubscribe = responder_sequence_unsubbed;
    if (dslink_node_set_meta(link, num, "$type", json_string("number")) != 0) {
        log_warn("Failed to set the type on the sequence\n");
        dslink_node_tree_free(link, num);
        return;
    }

    if (dslink_node_update_value_new(link, num, json_integer(0)) != 0) {
        log_warn("Failed to set the value on the sequence\n");
        dslink_node_tree_free(link, num);
        return;
    }

    if (dslink_node_add_child(link, num) != 0) {
        log_warn("Failed to add the sequence node to the root\n");
        dslink_node_tree_free(link, num);
    }
}
