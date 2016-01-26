#define LOG_TAG "msg_handler"
#include <dslink/log.h>

#include <string.h>
#include <dslink/ws.h>
#include "broker/msg_handler.h"

static
json_t *broker_list_root(json_t *rid) {
    if (!rid) {
        return NULL;
    }

    json_t *top = json_object();
    if (!top) {
        return NULL;
    }
    json_t *resps = json_array();
    if (!resps) {
        json_delete(top);
        return NULL;
    }
    json_t *resp = json_object();
    if (!resp) {
        json_delete(top);
        json_delete(resps);
        return NULL;
    }

    json_object_set_nocheck(top, "responses", resps);
    json_array_append_new(resps, resp);

    json_object_set_nocheck(resp, "rid", rid);
    json_object_set_new_nocheck(resp, "stream", json_string("open"));

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
json_t *broker_list_downstream(json_t *rid) {
    if (!rid) {
        return NULL;
    }

    json_t *top = json_object();
    if (!top) {
        return NULL;
    }
    json_t *resps = json_array();
    if (!resps) {
        json_delete(top);
        return NULL;
    }
    json_t *resp = json_object();
    if (!resp) {
        json_delete(top);
        json_delete(resps);
        return NULL;
    }

    json_object_set_nocheck(top, "responses", resps);
    json_array_append_new(resps, resp);

    json_object_set_nocheck(resp, "rid", rid);
    json_object_set_new_nocheck(resp, "stream", json_string("open"));

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

    return top;
fail:
    json_delete(top);
    return NULL;
}

static
int broker_handle_list(Broker *broker, json_t *req) {
    const char *path = json_string_value(json_object_get(req, "path"));
    if (!path) {
        return 1;
    }

    int ret = 0;
    if (strcmp(path, "/") == 0) {
        json_t *rid = json_object_get(req, "rid");
        json_t *resp = broker_list_root(rid);
        if (resp) {
            dslink_ws_send_obj(broker->ws, resp);
            json_delete(resp);
        } else {
            ret = 1;
        }
    } else if (strcmp(path, "/downstream") == 0) {
        json_t *rid = json_object_get(req, "rid");
        json_t *resp = broker_list_downstream(rid);
        if (resp) {
            dslink_ws_send_obj(broker->ws, resp);
            json_delete(resp);
        } else {
            ret = 1;
        }
    } else {
        log_err("Unhandled path: %s\n", path);
        ret = 1;
    }
    return ret;
}

static
void broker_handle_req(Broker *broker, json_t *req) {
    const char *method = json_string_value(json_object_get(req, "method"));
    if (!method) {
        return;
    }
    if (strcmp(method, "list") == 0) {
        broker_handle_list(broker, req);
    } else {
        log_err("Method unspecified: %s\n", method);
    }
}

void broker_handle_msg(Broker *broker,
                       json_t *data) {
    if (!data) {
        return;
    }
    json_incref(data);
    json_t *reqs = json_object_get(data, "requests");
    if (broker->link->isRequester && reqs) {
        json_t *req;
        size_t index = 0;
        json_array_foreach(reqs, index, req) {
            broker_handle_req(broker, req);
        }
    }

    json_t *resps = json_object_get(data, "responses");
    if (broker->link->isResponder && resps) {
        // TODO
    }

    json_decref(data);
}
