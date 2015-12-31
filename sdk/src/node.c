#include <string.h>
#include <assert.h>
#include "dslink/err.h"
#include "dslink/utils.h"
#include "dslink/node.h"

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

    DSNode *node = malloc(sizeof(DSNode));
    if (!node) {
        goto cleanup;
    }

    node->meta_data = NULL;
    node->children = NULL;
    node->on_list_open = NULL;
    node->on_list_close = NULL;

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
                              strlen(node->name), (void **) &tmp)) != 0) {
        return ret;
    }
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
        node = dslink_map_get(node->children, (void *) path, end - path);
        return dslink_node_get_path(node, end);
    } else if (*path != '\0') {
        if (!node->children) {
            return NULL;
        }
        return dslink_map_get(node->children, (void *) path, strlen(path));
    }

    return node;
}

void dslink_node_tree_free(DSNode *root) {
    DSLINK_CHECKED_EXEC(free, (void *) root->path);
    DSLINK_CHECKED_EXEC(free, (void *) root->name);
    DSLINK_CHECKED_EXEC(free, (void *) root->profile);
    if (root->children) {
        DSLINK_MAP_FREE(root->children, {
            DSLINK_CHECKED_EXEC(free, entry->key);
            ((DSNode *) entry->value)->name = NULL;
            DSLINK_CHECKED_EXEC(dslink_node_tree_free, entry->value);
        });
        free(root->children);
    }
    if (root->meta_data) {
        DSLINK_MAP_FREE(root->children, {
            free(entry->key);
            free(entry->value);
        });
        free(root->meta_data);
    }

    free(root);
}
