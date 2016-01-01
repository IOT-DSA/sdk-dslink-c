#define LOG_TAG "main"

#include <dslink/dslink.h>
#include <dslink/log.h>

static
void gen_number(void *data, EventLoop *loop) {
    DSLink *link = ((void **) data)[0];
    DSNode *node = ((void **) data)[1];
    if (!dslink_map_contains(link->responder->value_path_subs,
                             (void *) node->path)) {
        free((void **) data);
        return;
    }

    int x = rand();
    dslink_node_set_value(link, node, json_integer(x));
    dslink_event_loop_schedd(loop, gen_number, data, 1000);
}

static
void list_opened(DSLink *link, DSNode *node) {
    (void) link;
    log_info("List opened for: %s\n", node->path);
}

static
void list_closed(DSLink *link, DSNode *node) {
    (void) link;
    log_info("List closed for: %s\n", node->path);
}

static
void num_subbed(DSLink *link, DSNode *node) {
    log_info("Subscribed to %s\n", node->path);

    void **a = malloc(sizeof(void *) * 2);
    a[0] = link;
    a[1] = node;
    dslink_event_loop_schedd(&link->loop, gen_number, a, 1000);
}

static
void num_unsubbed(DSLink *link, DSNode *node) {
    (void) link;
    log_info("Unsubscribed to %s\n", node->path);
}

void init(DSLink *link) {
    DSNode *superRoot = link->responder->super_root;
    DSNode *a = dslink_node_create(superRoot, "a", "node");
    if (!a) {
        log_warn("Failed to create `a` node\n");
        return;
    }

    if (dslink_node_add_child(superRoot, a) != 0) {
        log_warn("Failed to add `a` to the super root node\n");
        dslink_node_tree_free(a);
        return;
    }

    DSNode *b = dslink_node_create(a, "b", "node");
    if (!b) {
        log_warn("Failed to create `b` node\n");
        return;
    }
    b->on_list_open = list_opened;
    b->on_list_close = list_closed;
    if (dslink_node_add_child(a, b) != 0) {
        log_warn("Failed to add `b` node to the `a` node\n");
        dslink_node_tree_free(b);
        return;
    }

    DSNode *num = dslink_node_create(superRoot, "num", "node");
    if (!num) {
        log_warn("Failed to create a number node\n");
        return;
    }

    num->on_subscribe = num_subbed;
    num->on_unsubscribe = num_unsubbed;
    if (dslink_node_set_meta(num, "$type", "number") != 0) {
        log_warn("Failed to set the type on the node\n");
        dslink_node_tree_free(num);
        return;
    }

    if (dslink_node_set_value(link, num, json_integer(0)) != 0) {
        log_warn("Failed to set the value on the node\n");
        dslink_node_tree_free(num);
        return;
    }

    if (dslink_node_add_child(superRoot, num) != 0) {
        log_warn("Failed to add the number node to the root\n");
        dslink_node_tree_free(num);
        return;
    }

    log_info("Initialized!\n");
}

void connected(DSLink *link) {
    (void) link;
    log_info("Connected!\n");
}

void disconnected(DSLink *link) {
    (void) link;
    log_info("Disconnected!\n");
}

int main(int argc, char **argv) {
    DSLinkCallbacks cbs = {
        init,
        connected,
        disconnected
    };

    return dslink_init(argc, argv, "C-Resp", 0, 1, &cbs);
}
