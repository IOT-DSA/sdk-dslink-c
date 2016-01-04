#include <string.h>
#include "dslink/msg/list_response.h"
#include "dslink/stream.h"
#include "dslink/ws.h"

static
void dslink_response_list_child_append_meta(json_t *obj,
                                            Map *meta,
                                            const char *name) {
    char *str = dslink_map_get(meta, (void *) name);
    if (str) {
        json_object_set_new(obj, name,
                            json_string(str));
    }
}

static
int dslink_response_list_append_update(json_t *updates,
                                       const char *key, json_t *value, uint8_t new) {
    json_t *str = json_string(key);
    if (!str) {
        return DSLINK_ALLOC_ERR;
    }

    json_t *update = json_array();
    if (!update) {
        json_delete(str);
        return DSLINK_ALLOC_ERR;
    }

    json_array_append_new(update, str);
    if (new) {
        json_array_append_new(update, value);
    } else {
        json_array_append(update, value);
    }
    json_array_append_new(updates, update);
    return 0;
}

int dslink_response_list_append_child(json_t *update, DSNode *child) {
    json_t *obj = json_object();
    if (!obj) {
        return DSLINK_ALLOC_ERR;
    }
    json_array_append_new(update, json_string(child->name));
    json_array_append_new(update, obj);

    json_object_set_new(obj, "$is", json_string(child->profile));
    if (child->meta_data) {
        Map *meta = child->meta_data;
        dslink_response_list_child_append_meta(obj, meta, "$name");
        dslink_response_list_child_append_meta(obj, meta, "$permission");
        dslink_response_list_child_append_meta(obj, meta, "$invokable");
        dslink_response_list_child_append_meta(obj, meta, "$type");
    }
    return 0;
}

int dslink_response_list(DSLink *link, json_t *req, DSNode *node) {
    if (!node) {
        return 1;
    }

    json_t *top = json_object();
    if (!top) {
        return 1;
    }

    json_t *resps = json_array();
    if (!resps) {
        return 1;
    }

    json_object_set_new_nocheck(top, "responses", resps);

    json_t *resp = json_object();
    if (!resp) {
        json_delete(top);
        return 1;
    }
    json_array_append_new(resps, resp);

    {
        json_t *updates = json_array();
        if (!updates) {
            json_delete(top);
            return 1;
        }
        json_object_set_new_nocheck(resp, "updates", updates);

        json_t *profile = json_string(node->profile);
        dslink_response_list_append_update(updates, "$is", profile, 1);
        if (node->meta_data) {
            dslink_map_foreach(node->meta_data) {
                const char *key = entry->key;
                json_t *val = entry->value;
                dslink_response_list_append_update(updates, key, val, 0);
            }
        }

        if (node->children) {
            dslink_map_foreach(node->children) {
                DSNode *val = entry->value;

                json_t *update = json_array();
                if (!update) {
                    json_delete(top);
                    return 1;
                }
                json_array_append_new(updates, update);
                dslink_response_list_append_child(update, val);
            }
        }
    }

    json_t *jsonRid = json_object_get(req, "rid");
    json_object_set_nocheck(resp, "rid", jsonRid);
    json_object_set_new_nocheck(resp, "stream", json_string("open"));

    {
        Stream *stream = malloc(sizeof(Stream));
        if (!stream) {
            json_delete(top);
            return 1;
        }
        stream->type = LIST_STREAM;
        stream->path = node->path;
        stream->on_close = node->on_list_close;

        uint32_t *rid = malloc(sizeof(uint32_t));
        if (!rid) {
            free(stream);
            json_delete(top);
            return 1;
        }
        {
            uint32_t r = (uint32_t) json_integer_value(jsonRid);
            *rid = r;
        }
        if (dslink_map_set(link->responder->open_streams,
                           rid, (void **) &stream) != 0) {
            free(rid);
            free(stream);
            json_delete(top);
            return 1;
        }

        void *p = rid;
        if (dslink_map_set(link->responder->list_subs,
                           (void *) node->path, &p) != 0) {
            free(dslink_map_remove(link->responder->open_streams,
                                   (void **) &rid));
            free(rid);
            free(stream);
            json_delete(top);
            return 1;
        }
        if (p) {
            free(p);
        }

        if (node->on_list_open) {
            node->on_list_open(link, node);
        }
    }

    {
        char *data = json_dumps(top, JSON_PRESERVE_ORDER);
        if (!data) {
            json_delete(top);
            const char *key = node->path;
            free(dslink_map_remove(link->responder->list_subs,
                              (void **) &key));
            return 1;
        }
        dslink_ws_send(link->_ws, data);
        free(data);
    }

    json_delete(top);
    return 0;
}
