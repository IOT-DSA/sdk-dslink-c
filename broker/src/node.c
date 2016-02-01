#include <stdlib.h>
#include <dslink/utils.h>
#include <string.h>
#include <jansson.h>
#include "broker/stream.h"
#include "broker/node.h"
#include "broker/msg/msg_list.h"

BrokerNode *broker_node_get(BrokerNode *root,
                            const char *path, char **out) {
    if (!root) {
        return NULL;
    } else if (strcmp(path, "/") == 0) {
        return root;
    } else if (*path == '/') {
        path++;
    }

    BrokerNode *node = root;
    const char *end = strchr(path, '/');
    if (end) {
        if (!node->children) {
            return NULL;
        }
        node = dslink_map_getl(node->children, (void *) path, end - path);
        if (node && node->type == DOWNSTREAM_NODE) {
            *out = (char *) end;
            return node;
        }
        return broker_node_get(node, end, out);
    } else if (*path != '\0') {
        if (!node->children) {
            return NULL;
        }
        return dslink_map_get(node->children, (void *) path);
    }

    return node;
}

BrokerNode *broker_node_create(const char *name, const char *profile) {
    profile = dslink_strdup(profile);
    if (!profile) {
        return NULL;
    }

    BrokerNode *node = calloc(1, sizeof(BrokerNode));
    if (!node) {
        return NULL;
    }

    node->type = REGULAR_NODE;
    node->name = dslink_strdup(name);
    if (!node->name) {
        free((void *) profile);
        free(node);
        return NULL;
    }

    node->children = malloc(sizeof(Map));
    if (dslink_map_init(node->children, dslink_map_str_cmp,
                        dslink_map_str_key_len_cal) != 0) {
        DSLINK_CHECKED_EXEC(free, node->children);
        free((void *) node->name);
        free((void *) profile);
        free(node);
        return NULL;
    }

    node->meta = json_object();
    if (!node->meta) {
        DSLINK_MAP_FREE(node->children, {});
        free((void *) node->name);
        free((void *) profile);
        free(node);
        return NULL;
    }
    listener_init(&node->on_value_update);
    listener_init(&node->on_child_added);
    listener_init(&node->on_child_removed);
    listener_init(&node->on_list_update);

    json_t *json = json_string(profile);
    json_object_set(node->meta, "$is", json);
    return node;
}

int broker_node_add(BrokerNode *parent, BrokerNode *child) {
    if (!(child && parent && parent->children)
        || dslink_map_contains(parent->children, (void *) child->name)) {
        return 1;
    }

    {
        size_t pathLen = strlen(parent->path);
        if (pathLen == 1 && *parent->path == '/') {
            pathLen = 0;
        }
        size_t nameLen = strlen(child->name);
        char *path = malloc(pathLen + nameLen + 2);
        child->path = path;
        if (!path) {
            return 1;
        }
        memcpy(path, parent->path, pathLen);
        *(path + pathLen) = '/';
        memcpy(path + pathLen + 1, child->name, nameLen + 1);
    }

    void *tmp = child;
    if (dslink_map_set(parent->children, (void *) child->name, &tmp) != 0) {
        return 1;
    }
    child->parent = parent;

    return 0;
}

void broker_node_free(BrokerNode *node) {
    if (!node) {
        return;
    }
    if (node->type == DOWNSTREAM_NODE) {
        DSLINK_MAP_FREE(&((DownstreamNode *)node)->list_streams, {
            free(entry->key);
        });
        listener_remove_all(&((DownstreamNode *)node)->on_link_connect);
        listener_remove_all(&((DownstreamNode *)node)->on_link_disconnect);
    } else {
        // TODO: add a new type for these listeners
        // they shouldn't be part of base node type
        listener_remove_all(&node->on_value_update);
        listener_remove_all(&node->on_child_added);
        listener_remove_all(&node->on_child_removed);
        listener_remove_all(&node->on_list_update);
    }

    if (node->parent) {
        void *tmp = (void *) node->name;
        dslink_map_remove(node->parent->children, &tmp);
    }

    if (node->children) {
        DSLINK_MAP_FREE(node->children, {
            BrokerNode *child = entry->value;
            child->parent = NULL;
            broker_node_free(child);
        });
        free(node->children);
    }

    json_decref(node->meta);
    free((void *) node->name);
    free(node);
}

uint32_t broker_node_incr_rid(DownstreamNode *node) {
    if (node->rid > (UINT32_MAX - 1)) {
        // Loop it around
        node->rid = 1;
    } else {
        node->rid++;
    }
    return node->rid;
}

void  broker_node_update_value(BrokerNode *node, json_t *value, uint8_t isNewValue) {
    if (node->value) {
        json_decref(value);
    }
    node->value = value;
    if (isNewValue) {

    } else {
        json_incref(value);
    }
    listener_dispatch_message(&node->on_value_update, node);
}

void broker_dslink_disconnect(DownstreamNode *node) {
    dslink_map_foreach(&node->list_streams) {
        BrokerListStream *stream = (BrokerListStream *)entry->value;
        broker_stream_list_disconnect(stream);
    }
    // notify all listeners of the close event
    listener_dispatch_message(&node->on_link_disconnect, NULL);

    node->link = NULL;
}

void broker_dslink_connect(DownstreamNode *node, RemoteDSLink *link) {
    node->link = link;
    dslink_map_foreach(&node->list_streams) {
        BrokerListStream *stream = (BrokerListStream *)entry->value;
        broker_stream_list_connect(stream, node);
    }
    // notify all listeners of the close event
    listener_dispatch_message(&node->on_link_connect, link);


}
