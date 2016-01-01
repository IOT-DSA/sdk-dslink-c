#include "dslink/ws.h"
#include "dslink/msg/sub_response.h"

static
int dslink_response_send_closed(DSLink *link, json_t *rid) {
    json_t *top = json_object();
    if (!top) {
        return DSLINK_ALLOC_ERR;
    }

    json_t *resps = json_array();
    if (!resps) {
        json_delete(top);
        return DSLINK_ALLOC_ERR;
    }
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    if (!resp) {
        json_delete(top);
        return DSLINK_ALLOC_ERR;
    }
    json_array_append_new(resps, resp);
    json_object_set(resp, "rid", rid);
    json_object_set_new_nocheck(resp, "stream", json_string("closed"));
    dslink_ws_send_obj(link->_ws, top);
    json_delete(top);
    return 0;
}

static
void dslink_response_send_init_val(DSLink *link,
                                   DSNode *node,
                                   uint32_t sid) {
    if (!node->value_timestamp) {
        return;
    }

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
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp,
                                "rid", json_integer(0));

    json_t *updates = json_array();
    if (!updates) {
        json_delete(top);
        return;
    }
    json_object_set_new_nocheck(resp, "updates", updates);

    json_t *update = json_array();
    if (!update) {
        json_delete(top);
        return;
    }

    json_array_append_new(updates, update);
    json_array_append_new(update, json_integer(sid));
    json_array_append(update, node->value);
    json_array_append(update, node->value_timestamp);

    dslink_ws_send_obj(link->_ws, top);
    json_delete(top);
}

int dslink_response_sub(DSLink *link, json_t *paths, json_t *rid) {
    if (dslink_response_send_closed(link, rid) != 0) {
        return DSLINK_ALLOC_ERR;
    }

    DSNode *root = link->responder->super_root;
    size_t index;
    json_t *value;
    json_array_foreach(paths, index, value) {
        const char *path = json_string_value(json_object_get(value, "path"));
        DSNode *node = dslink_node_get_path(root, path);
        if (!node) {
            continue;
        }
        uint32_t *sid = malloc(sizeof(uint32_t));
        if (!sid) {
            return DSLINK_ALLOC_ERR;
        }
        *sid = (uint32_t) json_integer_value(json_object_get(value, "sid"));
        void *tmp = sid;
        if (dslink_map_set(link->responder->value_path_subs,
                           (void *) node->path, &tmp) != 0) {
            free(sid);
            return 1;
        }
        if (tmp) {
            void *p = tmp;
            dslink_map_remove(link->responder->value_sid_subs, &p);
            free(tmp);
        }
        tmp = (void *) node->path;
        if (dslink_map_set(link->responder->value_sid_subs,
                           sid, &tmp) != 0) {
            tmp = (void *) node->path;
            dslink_map_remove(link->responder->value_path_subs, &tmp);
            free(sid);
            return 1;
        }

        dslink_response_send_init_val(link, node, *sid);
        if (node->on_subscribe) {
            node->on_subscribe(link, node);
        }
    }
    return 0;
}

int dslink_response_unsub(DSLink *link, json_t *sids, json_t *rid) {
    size_t index;
    json_t *value;
    json_array_foreach(sids, index, value) {
        uint32_t sid = (uint32_t) json_integer_value(value);
        void *p = &sid;
        char *path = dslink_map_remove(link->responder->value_sid_subs, &p);
        if (path) {
            DSNode *node = dslink_node_get_path(link->responder->super_root,
                                                path);
            if (node && node->on_unsubscribe) {
                node->on_unsubscribe(link, node);
            }

            void *tmp = path;
            dslink_map_remove(link->responder->value_path_subs, &tmp);
            free(p);
        }
    }

    return dslink_response_send_closed(link, rid);
}
