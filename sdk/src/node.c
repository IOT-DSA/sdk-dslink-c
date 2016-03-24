#include <string.h>
#include <assert.h>
#include "dslink/mem/mem.h"
#include "dslink/ws.h"
#include "dslink/msg/list_response.h"
#include "dslink/msg/sub_response.h"
#include "dslink/utils.h"

DSNode *dslink_node_create(DSNode *parent,
                           const char *name, const char *profile) {
    name = dslink_strdup(name);
    if (!name) {
        return NULL;
    }

    profile = dslink_strdup(profile);
    if (!profile) {
        dslink_free((void *) name);
        return NULL;
    }

    DSNode *node = dslink_calloc(1, sizeof(DSNode));
    if (!node) {
        goto cleanup;
    }

    node->parent = parent;
    node->name = name;
    node->profile = profile;

    if (parent) {
        size_t pathLen = strlen(parent->path);
        size_t nameLen = strlen(name);
        char *path = dslink_malloc(pathLen + nameLen + 2);
        node->path = path;
        if (!path) {
            goto cleanup;
        }
        memcpy(path, parent->path, pathLen);
        *(path + pathLen) = '/';
        memcpy(path + pathLen + 1, name, nameLen + 1);
    } else {
        node->path = dslink_calloc(1, sizeof(char));
        if (!node->path) {
            goto cleanup;
        }
    }

    return node;
cleanup:
    DSLINK_CHECKED_EXEC(dslink_free, (void *) name);
    DSLINK_CHECKED_EXEC(dslink_free, (void *) profile);
    if (node) {
        DSLINK_CHECKED_EXEC(dslink_free, (void *) node->path);
        dslink_free(node);
    }
    return NULL;
}

int dslink_node_add_child(DSLink *link, DSNode *node) {
    assert(node);
    assert(node->parent);
    int ret = 0;
    if (!node->parent->children) {
        node->parent->children = dslink_malloc(sizeof(Map));
        if (!node->parent->children) {
            return DSLINK_ALLOC_ERR;
        }
        if (dslink_map_init(node->parent->children,
                            dslink_map_str_cmp,
                            dslink_map_str_key_len_cal,
                            dslink_map_hash_key) != 0) {
            dslink_free(node->parent->children);
            node->parent->children = NULL;
            return DSLINK_ALLOC_ERR;
        }

    }

    assert(!dslink_map_contains(node->parent->children,
                                (void *) node->name));
    {
        if ((ret = dslink_map_set(node->parent->children,
                                  dslink_ref((char *) node->name, NULL),
                                  dslink_ref(node, NULL))) != 0) {
            return ret;
        }
    }

    if (!link->_ws) {
        return ret;
    }

    ref_t *refId = dslink_map_get(link->responder->list_subs,
                                  (void *) node->parent->path);
    if (!refId) {
        return ret;
    }
    uint32_t *id = refId->data;
    json_t *top = json_object();
    if (!top) {
        return ret;
    }
    json_t *resps = json_array();
    if (!resps) {
        goto cleanup;
    }
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    if (!resp) {
        goto cleanup;
    }
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp, "stream",
                                json_string("open"));
    json_object_set_new_nocheck(resp, "rid", json_integer(*id));
    json_t *updates = json_array();
    if (!updates) {
        goto cleanup;
    }
    json_object_set_new_nocheck(resp, "updates", updates);
    json_t *update = json_array();
    if (!update) {
        goto cleanup;
    }
    json_array_append_new(updates, update);
    dslink_response_list_append_child(update, node);
    dslink_ws_send_obj(link->_ws, top);
cleanup:
    json_delete(top);
    return ret;
}

DSNode *dslink_node_get_path(DSNode *root, const char *path) {
    if (!root) {
        return NULL;
    } else if (strcmp(path, "/") == 0) {
        return root;
    } else if (*path == '/') {
        path++;
    }

    DSNode *node = root;
    const char *end = strchr(path, '/');
    if (end) {
        if (!node->children) {
            return NULL;
        }
        ref_t *ref = dslink_map_getl(node->children, (void *) path, end - path);
        if (!ref) {
            return NULL;
        }
        node = ref->data;
        return dslink_node_get_path(node, end);
    } else if (*path != '\0') {
        if (!node->children) {
            return NULL;
        }
        ref_t *ref = dslink_map_get(node->children, (void *) path);
        if (!ref) {
            return NULL;
        }
        return ref->data;
    }

    return node;
}

void dslink_node_tree_free_basic(DSNode *root) {
    DSLINK_CHECKED_EXEC(dslink_free, (void *) root->path);
    DSLINK_CHECKED_EXEC(dslink_free, (void *) root->name);
    DSLINK_CHECKED_EXEC(dslink_free, (void *) root->profile);
    DSLINK_CHECKED_EXEC(json_delete, root->value_timestamp);
    DSLINK_CHECKED_EXEC(json_delete, root->value);
    if (root->children) {
        dslink_map_foreach_nonext(root->children) {
            dslink_decref(entry->key);
            {
                DSNode *child = entry->value->data;
                child->parent = NULL;
                dslink_node_tree_free_basic(child);
                dslink_decref(entry->value);
            }
            MapEntry *tmp = entry->next;
            free(entry->node);
            free(entry);
            entry = tmp;
        }
        dslink_free(root->children->table);
        dslink_free(root->children);
    }
    if (root->meta_data) {
        dslink_map_free(root->meta_data);
        dslink_free(root->meta_data);
    }

    // TODO: remove node from open_streams, list_subs, and value_path_subs

    dslink_free(root);
}

void dslink_node_tree_free(DSLink *link, DSNode *root) {
    if (link && link->_ws && root->parent && root->parent->name) {
        ref_t *rrid = dslink_map_get(link->responder->list_subs,
                                       (void *) root->parent->path);
        if (!rrid) {
            goto cleanup;
        }
        uint32_t *rid = rrid->data;
        json_t *top = json_object();
        uint8_t send = 0;
        if (top) {
            json_t *resps = json_array();
            if (resps) {
                json_object_set_new_nocheck(top, "responses", resps);
                json_t *resp = json_object();
                if (resp) {
                    json_array_append_new(resps, resp);
                    json_object_set_new_nocheck(resp, "rid",
                                                json_integer(*rid));
                    json_object_set_new_nocheck(resp, "stream",
                                                json_string("open"));
                    json_t *updates = json_array();
                    if (updates) {
                        json_object_set_new_nocheck(resp, "updates", updates);
                        json_t *update = json_object();
                        if (update) {
                            json_array_append_new(updates, update);
                            json_object_set_new_nocheck(update,
                                                        "name",
                                                        json_string(root->name));
                            json_object_set_new_nocheck(update,
                                                        "change",
                                                        json_string("remove"));
                            send = 1;
                        }
                    }
                }
            }
            if (send) {
                dslink_ws_send_obj(link->_ws, top);
            }
            json_delete(top);
        }
    }
cleanup:
    dslink_node_tree_free_basic(root);
}

int dslink_node_set_meta(DSLink *link, DSNode *node,
                         const char *name, json_t *value) {
    assert(node);
    assert(name);
    if (!node->meta_data) {
        if (!value) {
            return 0;
        }
        node->meta_data = dslink_malloc(sizeof(Map));
        if (!node->meta_data) {
            return DSLINK_ALLOC_ERR;
        }
        if (dslink_map_init(node->meta_data,
                            dslink_map_str_cmp,
                            dslink_map_str_key_len_cal,
                            dslink_map_hash_key) != 0) {
            dslink_free(node->meta_data);
            node->meta_data = NULL;
            return DSLINK_ALLOC_ERR;
        }
    }

    // TODO: send updates over the network

    if (!value) {
        dslink_map_remove(node->meta_data, (char *) name);
        return 0;
    }

    name = dslink_strdup(name);
    if (!name) {
        return DSLINK_ALLOC_ERR;
    }

    if (dslink_map_set(node->meta_data, dslink_ref((char *) name, free),
                       dslink_ref(value, (free_callback) json_decref)) != 0) {
        dslink_free((void *) name);
    }

    int ret = 0;

    if (!link->_ws) {
        return ret;
    }

    ref_t *refId = dslink_map_get(link->responder->list_subs,
                                  (void *) node->parent->path);
    if (!refId) {
        return ret;
    }
    uint32_t *id = refId->data;
    json_t *top = json_object();
    if (!top) {
        return ret;
    }
    json_t *resps = json_array();
    if (!resps) {
        goto cleanup;
    }
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *resp = json_object();
    if (!resp) {
        goto cleanup;
    }
    json_array_append_new(resps, resp);
    json_object_set_new_nocheck(resp, "stream",
                                json_string("open"));
    json_object_set_new_nocheck(resp, "rid", json_integer(*id));
    json_t *updates = json_array();
    if (!updates) {
        goto cleanup;
    }
    json_object_set_new_nocheck(resp, "updates", updates);
    json_t *update = json_array();
    if (!update) {
        goto cleanup;
    }
    json_array_append_new(updates, update);
    dslink_response_list_append_meta(update, node->meta_data, name);
    dslink_ws_send_obj(link->_ws, top);
    cleanup:
        json_delete(top);

    return ret;
}

int dslink_node_set_value(struct DSLink *link, DSNode *node, json_t *value) {
    char ts[32];
    dslink_create_ts(ts, sizeof(ts));

    json_t *jsonTs = json_string(ts);
    if (!jsonTs) {
        return DSLINK_ALLOC_ERR;
    }

    if (node->value_timestamp) {
        json_decref(node->value_timestamp);
    }

    if (node->value) {
        json_decref(node->value);
    }

    node->value_timestamp = jsonTs;
    node->value = value;

    ref_t *sid = dslink_map_get(link->responder->value_path_subs,
                                   (void *) node->path);
    if (sid) {
        dslink_response_send_val(link, node, *((uint32_t *) sid->data));
    }

    return 0;
}
