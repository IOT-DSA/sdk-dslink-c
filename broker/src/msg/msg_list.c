#include <string.h>

#define LOG_TAG "msg_list"
#include <dslink/log.h>
#include <dslink/ws.h>
#include "broker/msg/msg_list.h"

#define BROKER_CREATE_RESP(rid, stream) \
    json_t *top = json_object(); \
    if (!top) { \
        return NULL; \
    } \
    json_t *resps = json_array(); \
    if (!resps) { \
        json_delete(top); \
        return NULL; \
    } \
    json_t *resp = json_object(); \
    if (!resp) { \
        json_delete(top); \
        json_delete(resps); \
        return NULL; \
    } \
    json_object_set_new_nocheck(top, "responses", resps); \
    json_array_append_new(resps, resp); \
    json_object_set_nocheck(resp, "rid", rid); \
    json_object_set_new_nocheck(resp, "stream", json_string(stream))

static
json_t *broker_list_root(json_t *rid) {
    BROKER_CREATE_RESP(rid, "open");
    json_t *updates = json_array();
    if (!updates) {
        json_delete(top);
        return NULL;
    }
    json_object_set_new_nocheck(resp, "updates", updates);

    {
        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_array_append_new(up, json_string("$is"));
        json_array_append_new(up, json_string("node"));
        json_array_append_new(updates, up);
    }

    {
        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_t *node = json_object();
        if (!node) {
            json_delete(up);
            goto fail;
        }

        json_array_append_new(up, json_string("downstream"));
        json_array_append_new(up, node);

        json_object_set_new(node, "$is", json_string("node"));
        json_array_append_new(updates, up);
    }

    return top;
    fail:
    json_delete(top);
    return NULL;
}

static
json_t *broker_list_downstream(Broker *broker, json_t *rid) {
    BROKER_CREATE_RESP(rid, "open");

    json_t *updates = json_array();
    if (!updates) {
        json_delete(top);
        return NULL;
    }
    json_object_set_new_nocheck(resp, "updates", updates);

    {
        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_array_append_new(up, json_string("$is"));
        json_array_append_new(up, json_string("node"));
        json_array_append_new(updates, up);
    }

    dslink_map_foreach(&broker->downstream) {
        const char *name = ((RemoteDSLink *) entry->value)->name;

        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_t *node = json_object();
        if (!node) {
            json_delete(up);
            goto fail;
        }

        json_array_append_new(up, json_string(name));
        json_array_append_new(up, node);

        json_object_set_new(node, "$is", json_string("node"));
        json_array_append_new(updates, up);
    }

    return top;
    fail:
    json_delete(top);
    return NULL;
}

int broker_msg_handle_list(Broker *broker, json_t *req) {
    const char *path = json_string_value(json_object_get(req, "path"));
    json_t *rid = json_object_get(req, "rid");
    if (!(path && rid)) {
        return 1;
    }

    json_t *resp = NULL;
    if (strcmp(path, "/") == 0) {
        resp = broker_list_root(rid);
    } else if (strcmp(path, "/downstream") == 0) {
        resp = broker_list_downstream(broker, rid);
    } else {
        log_err("Unhandled path: %s\n", path);
    }

    if (!resp) {
        return 1;
    }
    dslink_ws_send_obj(broker->ws, resp);
    json_decref(resp);
    return 0;
}
