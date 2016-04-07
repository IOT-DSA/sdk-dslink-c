#define LOG_TAG "invoke"

#include <dslink/log.h>
#include <dslink/ws.h>
#include <dslink/stream.h>

static
void invoke_send_one_row(DSLink *link, DSNode *node,
                         json_t *rid, json_t *params, ref_t *stream_ref) {
    (void) node;
    (void) params;
    (void) stream_ref;
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
void invoke_send_echo(DSLink *link, DSNode *node,
                      json_t *rid, json_t *params, ref_t *stream_ref) {
    (void) node;
    (void) params;
    (void) stream_ref;
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

    json_t *msg = json_incref(json_object_get(params, "input"));

    json_array_append_new(update, msg);
    json_object_set_new_nocheck(resp, "updates", updates);
    json_array_append_new(resps, resp);

    json_object_set_new_nocheck(resp, "stream", json_string("closed"));
    json_object_set_nocheck(resp, "rid", rid);
    dslink_ws_send_obj((struct wslay_event_context *) link->_ws, top);
    json_delete(top);
}

static
void invoke_send_multiple_rows(DSLink *link, DSNode *node,
                               json_t *rid, json_t *params, ref_t *stream_ref) {
    (void) node;
    (void) params;
    (void) stream_ref;
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

static
void invoke_send_multiple_rows_multiple_updates(DSLink *link, DSNode *node,
                                                json_t *rid, json_t *params, ref_t *stream_ref) {
    (void) node;
    (void) params;
    (void) stream_ref;

    for (int x = 1; x <= 50; x++) {
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
        json_object_set_nocheck(resp, "rid", rid);
        if (x == 50) {
            json_object_set_new_nocheck(resp, "stream", json_string("closed"));
        }
        dslink_ws_send_obj((struct wslay_event_context *) link->_ws, top);
        json_delete(top);
    }
}

typedef struct NumberStreamHolder {
    json_t *rid;
    int *number;
    DSLink *link;
} NumberStreamHolder;

static
void do_stream_number_tick(uv_timer_t *timer) {
    NumberStreamHolder *holder = timer->data;

    ++(*holder->number);

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

    for (int i = 1; i <= 1; i++) {
        json_t *update = json_array();
        json_array_append_new(updates, update);
        json_array_append_new(update, json_integer(*holder->number));
    }

    json_object_set_new_nocheck(resp, "updates", updates);
    json_object_set_new_nocheck(resp, "stream", json_string("open"));
    json_array_append_new(resps, resp);
    json_object_set_nocheck(resp, "rid", holder->rid);
    dslink_ws_send_obj((struct wslay_event_context *) holder->link->_ws, top);
    json_delete(top);
}

static void invoke_onclose_stream_numbers(uv_handle_t *timer) {
    NumberStreamHolder *holder = timer->data;

    dslink_free(holder->number);
    dslink_free(holder);
    dslink_free(timer);
}

static void invoke_cancel_stream_numbers(DSLink *link, DSNode *node, void *stream_a) {
    (void) node;
    (void) link;
    Stream *stream = stream_a;
    uv_timer_t *timer = stream->data;
    uv_timer_stop(timer);
    uv_close((uv_handle_t *) timer, invoke_onclose_stream_numbers);
}

static
void invoke_send_streaming_numbers(DSLink *link, DSNode *node,
                                   json_t *rid, json_t *params, ref_t *stream_ref) {
    (void) node;
    (void) params;
    (void) stream_ref;

    NumberStreamHolder *holder = malloc(sizeof(NumberStreamHolder));
    Stream *stream = stream_ref->data;

    stream->unused = 1;

    json_incref(rid);
    holder->rid = rid;
    holder->link = link;
    holder->number = dslink_malloc(sizeof(int));
    *holder->number = 0;

    uv_timer_t *timer = dslink_malloc(sizeof(uv_timer_t));
    timer->data = holder;
    timer->close_cb = invoke_onclose_stream_numbers;
    uv_timer_init(&link->loop, timer);
    uv_timer_start(timer, do_stream_number_tick, 0, 1000);
    stream->on_close = invoke_cancel_stream_numbers;
    stream->data = timer;
}

void responder_init_invoke(DSLink *link, DSNode *root) {
    {
        DSNode *getOneRow = dslink_node_create(root, "getOneRow", "node");
        if (!getOneRow) {
            log_warn("Failed to create get one row action node\n");
            return;
        }

        getOneRow->on_invocation = invoke_send_one_row;
        dslink_node_set_meta(link, getOneRow, "$name", json_string("Get One Row"));
        dslink_node_set_meta(link, getOneRow, "$invokable", json_string("read"));

        json_t *columns = json_array();
        json_t *message_row = json_object();
        json_object_set_new(message_row, "name", json_string("message"));
        json_object_set_new(message_row, "type", json_string("string"));
        json_array_append_new(columns, message_row);
        dslink_node_set_meta(link, getOneRow, "$columns", columns);

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
        dslink_node_set_meta(link, getMultipleRows, "$name", json_string("Get Multiple Rows"));
        dslink_node_set_meta(link, getMultipleRows, "$invokable", json_string("read"));

        json_t *columns = json_array();
        json_t *message_row = json_object();
        json_object_set_new(message_row, "name", json_string("message"));
        json_object_set_new(message_row, "type", json_string("string"));
        json_array_append_new(columns, message_row);
        dslink_node_set_meta(link, getMultipleRows, "$columns", columns);

        dslink_node_set_meta(link, getMultipleRows, "$result", json_string("table"));

        if (dslink_node_add_child(link, getMultipleRows) != 0) {
            log_warn("Failed to add get multiple rows action to the root node\n");
            dslink_node_tree_free(link, getMultipleRows);
            return;
        }
    }

    {
        DSNode *getMultipleRowsUpdates = dslink_node_create(root, "getMultipleRowsUpdates", "node");
        if (!getMultipleRowsUpdates) {
            log_warn("Failed to create get multiple row action node\n");
            return;
        }

        getMultipleRowsUpdates->on_invocation = invoke_send_multiple_rows_multiple_updates;
        dslink_node_set_meta(link, getMultipleRowsUpdates, "$name", json_string("Get Multiple Rows and Updates"));
        dslink_node_set_meta(link, getMultipleRowsUpdates, "$invokable", json_string("read"));

        json_t *columns = json_array();
        json_t *message_row = json_object();
        json_object_set_new(message_row, "name", json_string("message"));
        json_object_set_new(message_row, "type", json_string("string"));
        json_array_append_new(columns, message_row);
        dslink_node_set_meta(link, getMultipleRowsUpdates, "$columns", columns);

        dslink_node_set_meta(link, getMultipleRowsUpdates, "$result", json_string("table"));

        if (dslink_node_add_child(link, getMultipleRowsUpdates) != 0) {
            log_warn("Failed to add get multiple rows action to the root node\n");
            dslink_node_tree_free(link, getMultipleRowsUpdates);
            return;
        }
    }

    {
        DSNode *getStreamNow = dslink_node_create(root, "getStreamNow", "node");
        if (!getStreamNow) {
            log_warn("Failed to create get stream now action node\n");
            return;
        }

        getStreamNow->on_invocation = invoke_send_streaming_numbers;
        dslink_node_set_meta(link, getStreamNow, "$name", json_string("Get Stream"));
        dslink_node_set_meta(link, getStreamNow, "$invokable", json_string("read"));

        json_t *columns = json_array();
        json_t *message_row = json_object();
        json_object_set_new(message_row, "name", json_string("value"));
        json_object_set_new(message_row, "type", json_string("number"));
        json_array_append_new(columns, message_row);
        dslink_node_set_meta(link, getStreamNow, "$columns", columns);

        dslink_node_set_meta(link, getStreamNow, "$result", json_string("stream"));

        if (dslink_node_add_child(link, getStreamNow) != 0) {
            log_warn("Failed to add get multiple rows action to the root node\n");
            dslink_node_tree_free(link, getStreamNow);
            return;
        }
    }

    {
        DSNode *echoNode = dslink_node_create(root, "echo", "node");
        if (!echoNode) {
            log_warn("Failed to create echo action node\n");
            return;
        }

        echoNode->on_invocation = invoke_send_echo;
        dslink_node_set_meta(link, echoNode, "$name", json_string("Echo"));
        dslink_node_set_meta(link, echoNode, "$invokable", json_string("read"));

        json_t *columns = json_array();
        json_t *message_row = json_object();
        json_object_set_new(message_row, "name", json_string("message"));
        json_object_set_new(message_row, "type", json_string("string"));

        json_t *message_param = json_object();
        json_object_set_new(message_row, "name", json_string("input"));
        json_object_set_new(message_row, "type", json_string("string"));

        json_array_append_new(columns, message_row);

        json_t *params = json_array();
        json_array_append_new(params, message_param);

        dslink_node_set_meta(link, echoNode, "$columns", columns);
        dslink_node_set_meta(link, echoNode, "$params", params);

        if (dslink_node_add_child(link, echoNode) != 0) {
            log_warn("Failed to add echo action to the root node\n");
            dslink_node_tree_free(link, echoNode);
            return;
        }
    }
}
