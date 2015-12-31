#define LOG_TAG "main"

#include <dslink/dslink.h>
#include <dslink/log.h>

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
