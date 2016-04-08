#include <string.h>
#include "dslink/mem/mem.h"
#include "dslink/utils.h"
#include "dslink/msg/list_response.h"
#include "dslink/stream.h"
#include "dslink/ws.h"

void dslink_response_list_append_meta(json_t *obj,
                                            Map *meta,
                                            const char *name) {
    ref_t *val = dslink_map_get(meta, (void *) name);
    if (val) {
        json_object_set(obj, name, val->data);
    }
}

static
int dslink_response_list_append_update(json_t *updates,
                                       const char *key, json_t *value, uint8_t new) {
    json_t *str = json_string_nocheck(key);
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
    json_array_append_new(update, json_string_nocheck(child->name));
    json_array_append_new(update, obj);

    json_object_set_new(obj, "$is", json_string_nocheck(child->profile));
    if (child->meta_data) {
        Map *meta = child->meta_data;
        dslink_response_list_append_meta(obj, meta, "$name");
        dslink_response_list_append_meta(obj, meta, "$permission");
        dslink_response_list_append_meta(obj, meta, "$invokable");
        dslink_response_list_append_meta(obj, meta, "$type");
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

        json_t *profile = json_string_nocheck(node->profile);
        dslink_response_list_append_update(updates, "$is", profile, 1);
        if (node->meta_data) {
            dslink_map_foreach(node->meta_data) {
                const char *key = entry->key->data;

                if (strncmp(key, "$$$", 3) == 0) {
                    continue;
                }

                json_t *val = entry->value->data;
                dslink_response_list_append_update(updates, key, val, 0);
            }
        }

        if (node->children) {
            dslink_map_foreach(node->children) {
                DSNode *val = entry->value->data;

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
    json_object_set_new_nocheck(resp, "stream", json_string_nocheck("open"));

    {
        Stream *stream = dslink_malloc(sizeof(Stream));
        if (!stream) {
            json_delete(top);
            return 1;
        }
        stream->type = LIST_STREAM;
        stream->path = dslink_strdup(node->path);
        stream->on_close = node->on_list_close;
        if (!stream->path) {
            json_delete(top);
            dslink_free(stream);
            return 1;
        }

        ref_t *rid = dslink_ref(dslink_malloc(sizeof(uint32_t)), dslink_free);
        if (!rid) {
            dslink_free((void *) stream->path);
            dslink_free(stream);
            json_delete(top);
            return 1;
        }
        
        {
            uint32_t r = (uint32_t) json_integer_value(jsonRid);
            *((uint32_t *) rid->data) = r;
        }

        if (dslink_map_set(link->responder->open_streams,
                           rid,
                           dslink_ref(stream, free)) != 0) {
            dslink_free(rid);
            dslink_free(stream);
            json_delete(top);
            return 1;
        }

        if (dslink_map_set(link->responder->list_subs,
                           dslink_ref((void *) stream->path, dslink_free),
                           dslink_incref(rid)) != 0) {
            dslink_map_remove(link->responder->open_streams, rid);
            dslink_free(rid);
            dslink_free((void *) stream->path);
            dslink_free(stream);
            json_delete(top);
            return 1;
        }

        if (node->on_list_open) {
            node->on_list_open(link, node);
        }
    }

    {
        char *data = json_dumps(top, JSON_PRESERVE_ORDER);
        if (!data) {
            json_delete(top);
            dslink_map_remove(link->responder->list_subs,
                              (char *) node->path);
            return 1;
        }
        dslink_ws_send(link->_ws, data);
        dslink_free(data);
    }

    json_delete(top);
    return 0;
}
