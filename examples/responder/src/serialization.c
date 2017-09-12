#define LOG_TAG "serialization"

#include <dslink/log.h>
#include "serialization.h"

#include <strings.h>

static
void save_node(uv_timer_t* timer) {
    DSLink *link = timer->loop->data;
    DSNode *node = timer->data;
    timer->data = NULL;
    json_t *json = dslink_node_serialize(link, node);
    json_dump_file(json, "saved_node.json", 0);
    json_decref(json);
}

static
uv_timer_t save_timer;

static
void on_node_changed(DSLink *link, DSNode *node) {
    if (save_timer.data){
        return;
    }
    save_timer.data = node;
    uv_timer_init(&link->loop, &save_timer);
    uv_timer_start(&save_timer, save_node, 100, 0);
}

static
void load_node(DSLink *link, DSNode *node) {
    json_error_t err;
    json_t *json = json_load_file("saved_node.json", 0 , &err);
    if (json) {
        dslink_node_deserialize(link, node, json);
        json_decref(json);
    }
}

void responder_init_serialization(DSLink *link, DSNode *root) {
    bzero(&save_timer, 0);
    DSNode *node = dslink_node_create(root, "saved", "node");

    // data for serialization testing
    dslink_node_set_meta_new(link, node, "$$$password", json_string_nocheck("Test1234"));
    // load the data after set password to test if the deserialization is correct
    load_node(link, node);
    dslink_node_set_meta_new(link, node, "$writable", json_string_nocheck("write"));
    dslink_node_set_meta_new(link, node, "$type", json_string_nocheck("string"));
    if (dslink_node_add_child(link, node) != 0) {
        log_warn("Failed to add the serialization node to the root\n");
        dslink_node_tree_free(link, node);
    }

    node->on_data_changed = on_node_changed;
}
