#include <broker/node.h>
#include <string.h>

void virtual_downstream_node_init(VirtualDownstreamNode *node) {
    node->permissionList = NULL;
    dslink_map_init(&node->childrenNode, dslink_map_str_cmp,
                    dslink_map_str_key_len_cal, dslink_map_hash_key);
    node->meta = json_object();
}

void virtual_downstream_node_free(VirtualDownstreamNode *pnode) {
    json_decref(pnode->meta);
    virtual_downstream_free_map(&pnode->childrenNode);
    permission_list_free(pnode->permissionList);
    dslink_free(pnode);
}

void virtual_downstream_free_map(Map *map) {
    dslink_map_foreach(map) {
        VirtualDownstreamNode* node = entry->value->data;
        virtual_downstream_node_free(node);
    }
    dslink_map_free(map);
}


json_t *set_virtual_attribute(const char* path,
                                             VirtualDownstreamNode* node, const char *key, json_t *value) {
    if (!path || *path == 0) {
        if (key) {
            if (value){
                json_object_set_nocheck(node->meta, key, value);
            } else {
                json_object_del(node->meta, key);
            }
        }
        return node->meta;
    } else {
        const char* next = strstr(path, "/");
        char* name;
        if (next) {
            name = dslink_calloc(next - path + 1, 1);
            memcpy(name, path, next-path);
            next ++; // remove '/'
        } else {
            name = (char*)path;
        }
        ref_t *ref = dslink_map_get(&node->childrenNode, name);
        VirtualDownstreamNode *child;
        if (ref && ref->data) {
            child = ref->data;
        } else {
            if (!key) {
                return NULL;
            }
            child = dslink_calloc(1, sizeof(VirtualDownstreamNode));
            virtual_downstream_node_init(child);
            dslink_map_set(&node->childrenNode, dslink_str_ref(name), dslink_ref(child, NULL));
        }
        return set_virtual_attribute(next, child, key, value);
    }
}

json_t *set_downstream_attribute(const char* path, DownstreamNode* node, const char *key, json_t *value) {
    if (!path || *path == 0) {
        if (key) {
            if (value){
                json_object_set_nocheck(node->meta, key, value);
            } else {
                json_object_del(node->meta, key);
            }
        }
        return node->meta;
    } else {
        const char* next = strstr(path, "/");
        char* name;
        if (next) {
            name = dslink_calloc(next - path + 1, 1);
            memcpy(name, path, next-path);
            next ++; // remove '/'
        } else {
            name = (char*)path;
        }

        ref_t *ref = dslink_map_get(&((DownstreamNode *)node)->children_permissions, name);
        VirtualDownstreamNode *child;
        if (ref && ref->data) {
            child = ref->data;
        } else {
            if (!key) {
                return NULL;
            }
            child = dslink_calloc(1, sizeof(VirtualDownstreamNode));
            virtual_downstream_node_init(child);
            dslink_map_set(&node->children_permissions, dslink_str_ref(name), dslink_ref(child, NULL));
        }
        return set_virtual_attribute(next, child, key, value);
    }
}
