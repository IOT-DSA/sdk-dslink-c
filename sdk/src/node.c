#include <string.h>
#include <assert.h>
#include "dslink/msg/sub_response.h"
#include "dslink/err.h"
#include "dslink/utils.h"

DSNode *dslink_node_create(DSNode *parent,
                           const char *name, const char *profile) {
    name = dslink_strdup(name);
    if (!name) {
        return NULL;
    }

    profile = dslink_strdup(profile);
    if (!profile) {
        free((void *) name);
        return NULL;
    }

    DSNode *node = calloc(1, sizeof(DSNode));
    if (!node) {
        goto cleanup;
    }

    node->name = name;
    node->profile = profile;

    if (parent) {
        size_t pathLen = strlen(parent->path);
        size_t nameLen = strlen(name);
        char *path = malloc(pathLen + nameLen + 2);
        node->path = path;
        if (!path) {
            goto cleanup;
        }
        memcpy(path, parent->path, pathLen);
        *(path + pathLen) = '/';
        memcpy(path + pathLen + 1, name, nameLen + 1);
    } else {
        node->path = calloc(1, sizeof(char));
        if (!node->path) {
            goto cleanup;
        }
    }

    return node;
cleanup:
    DSLINK_CHECKED_EXEC(free, (void *) name);
    DSLINK_CHECKED_EXEC(free, (void *) profile);
    if (node) {
        DSLINK_CHECKED_EXEC(free, (void *) node->path);
        free(node);
    }
    return NULL;
}

int dslink_node_add_child(DSNode *parent, DSNode *node) {
    assert(parent);
    assert(node);
    int ret = 0;
    if (!parent->children) {
        parent->children = malloc(sizeof(Map));
        if (!parent->children) {
            return DSLINK_ALLOC_ERR;
        }
        if (dslink_map_init(parent->children,
                            dslink_map_str_cmp,
                            dslink_map_str_key_len_cal) != 0) {
            free(parent->children);
            parent->children = NULL;
            return DSLINK_ALLOC_ERR;
        }

    }

    DSNode *tmp = node;
    if ((ret = dslink_map_set(parent->children, (void *) node->name,
                              (void **) &tmp)) != 0) {
        return ret;
    }

    // TODO: send it over the network if there is a path sub

    return 0;
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
        node = dslink_map_getl(node->children, (void *) path, end - path);
        return dslink_node_get_path(node, end);
    } else if (*path != '\0') {
        if (!node->children) {
            return NULL;
        }
        return dslink_map_get(node->children, (void *) path);
    }

    return node;
}

void dslink_node_tree_free(DSNode *root) {
    DSLINK_CHECKED_EXEC(free, (void *) root->path);
    DSLINK_CHECKED_EXEC(free, (void *) root->name);
    DSLINK_CHECKED_EXEC(free, (void *) root->profile);
    DSLINK_CHECKED_EXEC(json_delete, root->value_timestamp);
    DSLINK_CHECKED_EXEC(json_delete, root->value);
    if (root->children) {
        DSLINK_MAP_FREE(root->children, {
            DSLINK_CHECKED_EXEC(free, entry->key);
            ((DSNode *) entry->value)->name = NULL;
            DSLINK_CHECKED_EXEC(dslink_node_tree_free, entry->value);
        });
        free(root->children);
    }
    if (root->meta_data) {
        DSLINK_MAP_FREE(root->meta_data, {
            free(entry->key);
            free(entry->value);
        });
        free(root->meta_data);
    }

    // TODO: remove node from open_streams, list_subs, and value_path_subs

    free(root);
}

int dslink_node_set_meta(DSNode *node,
                         const char *name, const char *value) {
    assert(node);
    assert(name);
    if (!node->meta_data) {
        if (!value) {
            return 0;
        }
        node->meta_data = malloc(sizeof(Map));
        if (!node->meta_data) {
            return DSLINK_ALLOC_ERR;
        }
        if (dslink_map_init(node->meta_data,
                            dslink_map_str_cmp,
                            dslink_map_str_key_len_cal) != 0) {
            free(node->meta_data);
            node->meta_data = NULL;
            return DSLINK_ALLOC_ERR;
        }
    }

    // TODO: send updates over the network

    if (!value) {
        const char *tmp = name;
        char *v = dslink_map_remove(node->meta_data, (void **) &tmp);
        if (v) {
            free((void **) tmp);
            free(v);
        }
        return 0;
    }

    name = dslink_strdup(name);
    if (!name) {
        return DSLINK_ALLOC_ERR;
    }

    value = dslink_strdup(value);
    if (!value) {
        return DSLINK_ALLOC_ERR;
    }

    const char *tmp = value;
    if (dslink_map_set(node->meta_data,
                       (void *) name, (void **) &tmp) != 0) {
        free((void *) name);
        free((void *) value);
    }
    if (tmp) {
        free((void *) tmp);
    }
    return 0;
}

int dslink_node_set_value(struct DSLink *link, DSNode *node, json_t *value) {
    char ts[32];
    dslink_create_ts(ts, sizeof(ts));

    json_t *jsonTs = json_string(ts);
    if (!jsonTs) {
        return DSLINK_ALLOC_ERR;
    }

    if (node->value_timestamp) {
        json_delete(node->value_timestamp);
    }

    if (node->value) {
        json_delete(node->value);
    }

    node->value_timestamp = jsonTs;
    node->value = value;

    uint32_t *sid = dslink_map_get(link->responder->value_path_subs,
                                   (void *) node->path);
    if (sid) {
        dslink_response_send_val(link, node, *sid);
    }

    return 0;
}
