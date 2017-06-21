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

    // superRoot = `/`
    DSNode *superRoot = link->responder->super_root;

    //  `/string` 노드를 생성하고, Node 를 설정한다. 
    //
    //      Node config https://github.com/IOT-DSA/docs/wiki/Configs
    //      Value type  https://github.com/IOT-DSA/docs/wiki/Value-Types
    //
    //      /string 노드 속성은
    //          문자열 타입이며, subscribe 가능 ($type : string)
    //          이 노드에 set 메소드 호출 가능 ($writable : write)
    //          
    DSNode *stringValueNode = dslink_node_create(superRoot, "string", "node");
    dslink_node_set_meta(link, stringValueNode, "$type", json_string("string"));
    dslink_node_set_meta(link, stringValueNode, "$writable", json_string("write"));    
    //
    //  `/string` 노드에 "Hello World!" 값을 설정한다. 만일 해당 노드에 
    //  subscriber 에게 업데이트된 값을 전송한다. 
    //
    dslink_node_update_value_new(link, stringValueNode, json_string("Hello World!"));

    // 
    //  dslink_node_add_child() 를 호출해서 dslink 에 새로운 자식 노드를 등록한다.
    //  dslink_node_add_child() 함수는 부모 노드에 등록된 subscriber 에게 child node 의
    //  추가를 알리기 위해 Response 를 전송한다. 
    //  
    //  Response (https://github.com/IOT-DSA/docs/wiki/Node-API#responses) 는 
    //  dslink 와 연결된 broker 에게 web socket 을 통해서 전송하는데, 현재 init() 함수가
    //  호출되는 시점은 아직 link->_ws 소켓이 생성되기 전이라서 response 를 
    //  broker 로 전송하지는 않는다. 
    //      
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
