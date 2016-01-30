#include <stdlib.h>
#include <dslink/col/map.h>
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

    node->parent = NULL;
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

    json_t *json = json_string(profile);
    json_object_set(node->meta, "$is", json);
    return node;
}

int broker_node_add(BrokerNode *parent, BrokerNode *child) {
    if (!(child && parent && parent->children)) {
        return 1;
    }

    if (dslink_map_contains(parent->children, (void *) child->name)) {
        return 1;
    }

    void *tmp = child;
    return dslink_map_set(parent->children, (void *) child->name, &tmp);
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
    }

    if (node->parent) {
        void *tmp = (void *) node->name;
        dslink_map_remove(node->parent->children, &tmp);
    }

    if (node->children) {
        DSLINK_MAP_FREE(node->children, {
            broker_node_free(entry->value);
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


void broker_dslink_disconnect(DownstreamNode *node) {
    dslink_map_foreach(&node->list_streams) {
        BrokerListStream *stream = (BrokerListStream *)entry->value;
        broker_stream_list_disconnect(stream);
    }
    // notify all listeners of the close event
    listener_dispatch_message(&node->on_link_disconnect, NULL);

    node->link = NULL;
}