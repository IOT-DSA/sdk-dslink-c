//
// Created by ali on 17.01.2017.
//
/*
 * test node created first.
 * test steps are running sequentially, ending test calls the next step.
 * test steps:
 * 1) get test node value : compares with the init value
 * 2) set test node value
 * 3) run async -> gets the test node value and compares with the set value in step 2
 * If everything was successful, removes the test node.
 */

#define LOG_TAG "threadsafe_api_test"

#include "dslink/threadsafe_api_test.h"
#include <dslink/log.h>
#include <string.h>
#include <assert.h>

#define PRINT_MODE // otherwise assert mode

void threadsafe_api_test1(void *arg);
void threadsafe_api_test2(void *arg);
void threadsafe_api_test3(void *arg);

int testRes;

void async_run_callback_test3(DSLink *link, void* cbData) {

#ifdef PRINT_MODE
    if(!link) {
        log_warn("link error\n");
        testRes = 0;
    }

    if(strcmp(cbData, "tst")) {
        log_warn("callback data error\n");
        testRes = 0;
    }
#else
    assert(link);
    assert(cbData);
#endif

    if(link) {
        DSNode *node = dslink_node_get_path(link->responder->super_root, "test_node");
        if (node) {
#ifdef PRINT_MODE
            if(strcmp(json_string_value(node->value), "Changed_TestNodeVal")) {
                log_warn("set node value error\n");
                testRes = 0;
            }
#else
            assert(!strcmp(json_string_value(node->value), "Changed_TestNodeVal"));
#endif
        } else
            testRes = 0;
    } else
        testRes = 0;

    dslink_free(cbData);

    if(testRes) {
        log_info("All Tests Done!\n");

        //delete the node after test
        ref_t *nodeToRemove = dslink_map_remove_get(link->responder->super_root->children, "test_node");
        if (nodeToRemove) {
            dslink_node_tree_free(link, nodeToRemove->data);
            dslink_decref(nodeToRemove);
        }


    } else {
        log_info("Test failed\n");
    }
}

void threadsafe_api_test3(void *arg) {

    char *sTest = (char*)dslink_malloc(4*sizeof(char));
    sTest[0]='t';
    sTest[1]='s';
    sTest[2]='t';
    sTest[3]=0;
    dslink_run_safe((DSLink*)arg,async_run_callback_test3,sTest);

}
void nodval_async_set_callback_test2(int res, void* cbData) {

#ifdef PRINT_MODE
    if(!cbData) {
        log_warn("callback data error\n");
        testRes = 0;
    }
    if(res) {
        log_warn("test node value set error\n");
        testRes = 0;
    }
#else
    assert(cbData);
    assert(!res);
#endif

//    dslink_free(cbData);
    if(testRes) {
        log_info("Test 2 done\n");
        threadsafe_api_test3((DSLink *) cbData);
    }
}

void threadsafe_api_test2(void *arg) {
    dslink_node_update_value_safe((DSLink*)arg,
                                  strdup("test_node"),
                                  json_string("Changed_TestNodeVal"),
                                  nodval_async_set_callback_test2,
                                  arg);

}

void nodval_async_get_callback_test1(json_t *retVal, void* cbData) {

#ifdef PRINT_MODE
    if(!cbData) {
        log_warn("callback data error\n");
        testRes = 0;
    }
    if(strcmp(json_string_value(retVal), "TestNodeVal_1")) {
        log_warn("test node value get error\n");
        testRes = 0;
    }
    if(retVal->refcount != 1) {
        log_warn("return json value error\n");
        testRes = 0;
    }
#else
    assert(cbData);
    assert(!strcmp(json_string_value(retVal), "TestNodeVal_1"));
    assert(retVal->refcount == 1)
#endif

//    dslink_free(cbData);
    json_decref(retVal);

    if(testRes) {
        log_info("Test 1 done\n");
        threadsafe_api_test2((DSLink *) cbData);
    }
}

void threadsafe_api_test1(void *arg) {

    dslink_node_get_value_safe((DSLink*)arg,strdup("test_node"),nodval_async_get_callback_test1,arg);

}

int run_threadsafe_api_tests(DSLink *link) {

    int ret;
#ifdef PRINT_MODE
    if(!link)
        return 0;
#else
    assert(link);
#endif

    // create a node to test
    DSNode *testNode = dslink_node_create(link->responder->super_root, "test_node", "node");
#ifdef PRINT_MODE
    if (!testNode) {
        log_warn("Failed to create the test node\n");
        return 0;
    }
#else
    assert(testNode);
#endif
    dslink_node_set_meta(link, testNode, "$type", json_string("string"));
    dslink_node_set_value(link, testNode, json_string("TestNodeVal_1"));

    ret = dslink_node_add_child(link, testNode);

#ifdef PRINT_MODE
    if (ret != 0) {
        log_warn("Failed to add the Test node to the root\n");
        dslink_node_tree_free(link, testNode);
        return 0;
    }
#else
    assert(ret == 0);
#endif

    testRes = 1;

    uv_thread_t new_thread_id;
    uv_thread_create(&new_thread_id, threadsafe_api_test1, link);

    uv_thread_join(&new_thread_id);

    return 1;
}