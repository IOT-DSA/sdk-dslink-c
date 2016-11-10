#define LOG_TAG "main"

#include <dslink/log.h>
#include <dslink/storage/storage.h>
#include <dslink/node.h>

#include "replicator.h"
#include "rng.h"
#include "invoke.h"
#include "serialization.h"

// Called to initialize your node structure.
void init(DSLink *link) {
    json_t *messageValue = dslink_json_get_config(link, "message");
    if (messageValue) {
        log_info("Message = %s\n", json_string_value(messageValue));
    }

    DSNode *superRoot = link->responder->super_root;

    DSNode *stringValueNode = dslink_node_create(superRoot, "string", "node");
    dslink_node_set_meta(link, stringValueNode, "$type", json_string("string"));
    dslink_node_set_meta(link, stringValueNode, "$writable", json_string("write"));
    dslink_node_set_value_new(link, stringValueNode, json_string("Hello World!"));
    dslink_node_add_child(link, stringValueNode);
    
    responder_init_replicator(link, superRoot);
    responder_init_rng(link, superRoot);
    responder_init_invoke(link, superRoot);
    responder_init_serialization(link, superRoot);

    // add link data
    json_t * linkData = json_object();
    json_object_set_nocheck(linkData, "test", json_true());
    link->link_data = linkData;

    log_info("Initialized!\n");
}

// Called when the DSLink is connected.
void connected(DSLink *link) {
    (void) link;
    log_info("Connected!\n");
}

// Called when the DSLink is disconnected.
// If this was not initiated by dslink_close,
// then a reconnection attempt is made.
void disconnected(DSLink *link) {
    (void) link;
    log_info("Disconnected!\n");
}

// The main function.
int main(int argc, char **argv) {
    DSLinkCallbacks cbs = { // Create our callback struct.
        init, // init_cb
        connected, //on_connected_cb
        disconnected, // on_disconnected_cb
        NULL // on_requester_ready_cb
    };

    // Initializes a DSLink and handles reconnection.
    // Pass command line arguments, our dsId,
    // are we a requester?, are we a responder?, and a reference to our callbacks.
    return dslink_init(argc, argv, "C-Responder", 0, 1, &cbs);
}
