#define LOG_TAG "invoke"

#include <dslink/log.h>
#include <dslink/ws.h>

static
void invoke_send_one_row(DSLink *link, DSNode *node,
                  json_t *rid, json_t *params) {
    (void) node;
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
    json_t *updates = json_array();
    json_t *update = json_array();
    json_array_append_new(updates, update);
    json_array_append_new(update, json_string("Hello World"));
    json_object_set_new_nocheck(resp, "updates", updates);
    json_array_append_new(resps, resp);

    json_object_set_new_nocheck(resp, "stream", json_string("closed"));
    json_object_set_nocheck(resp, "rid", rid);
    dslink_ws_send_obj((struct wslay_event_context *) link->_ws, top);
    json_delete(top);
}

static
void invoke_send_multiple_rows(DSLink *link, DSNode *node,
                         json_t *rid, json_t *params) {
    (void) node;
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
    json_t *updates = json_array();

    for (int i = 1; i <= 5; i++) {
        json_t *update = json_array();
        json_array_append_new(updates, update);
        json_array_append_new(update, json_string("Hello World"));
    }

    json_object_set_new_nocheck(resp, "updates", updates);
    json_array_append_new(resps, resp);

    json_object_set_new_nocheck(resp, "stream", json_string("closed"));
    json_object_set_nocheck(resp, "rid", rid);
    dslink_ws_send_obj((struct wslay_event_context *) link->_ws, top);
    json_delete(top);
}

void responder_init_invoke(DSLink *link, DSNode *root) {
    {
        DSNode *getOneRow = dslink_node_create(root, "getOneRow", "node");
        if (!getOneRow) {
            log_warn("Failed to create get one row action node\n");
            return;
        }

        getOneRow->on_invocation = invoke_send_one_row;
        dslink_node_set_meta(getOneRow, "$name", json_string("Get One Row"));
        dslink_node_set_meta(getOneRow, "$invokable", json_string("read"));

        json_t *columns = json_array();
        json_t *message_row = json_object();
        json_object_set_new(message_row, "name", json_string("message"));
        json_object_set_new(message_row, "type", json_string("string"));
        json_array_append_new(columns, message_row);
        dslink_node_set_meta(getOneRow, "$columns", columns);

        if (dslink_node_add_child(link, getOneRow) != 0) {
            log_warn("Failed to add get one row action to the root node\n");
            dslink_node_tree_free(link, getOneRow);
            return;
        }
    }

    {
        DSNode *getMultipleRows = dslink_node_create(root, "getMultipleRows", "node");
        if (!getMultipleRows) {
            log_warn("Failed to create get multiple row action node\n");
            return;
        }

        getMultipleRows->on_invocation = invoke_send_multiple_rows;
        dslink_node_set_meta(getMultipleRows, "$name", json_string("Get Multiple Rows"));
        dslink_node_set_meta(getMultipleRows, "$invokable", json_string("read"));

        json_t *columns = json_array();
        json_t *message_row = json_object();
        json_object_set_new(message_row, "name", json_string("message"));
        json_object_set_new(message_row, "type", json_string("string"));
        json_array_append_new(columns, message_row);
        dslink_node_set_meta(getMultipleRows, "$columns", columns);

        dslink_node_set_meta(getMultipleRows, "$result", json_string("table"));

        if (dslink_node_add_child(link, getMultipleRows) != 0) {
            log_warn("Failed to add get multiple rows action to the root node\n");
            dslink_node_tree_free(link, getMultipleRows);
            return;
        }
    }
}
