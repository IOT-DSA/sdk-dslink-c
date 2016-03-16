
#include "broker/permission/permission.h"
#include <broker/node.h>
#include <broker/remote_dslink.h>
#include <string.h>

void permission_groups_init(PermissionGroups* groups) {
    groups->groups = NULL;
    groups->groupLen = 0;
}
void permission_groups_free(PermissionGroups* groups) {
    if (groups->groups) {
        for (size_t i = 0; i < groups->groupLen; ++i) {
            dslink_free((void *)groups->groups[i]);
        }
        dslink_free(groups->groups);
    }
}
void virtual_permission_init(VirtualPermissionNode* node) {
    node->permissionList = NULL;
    dslink_map_init(&node->childrenNode, dslink_map_str_cmp,
                    dslink_map_str_key_len_cal, dslink_map_hash_key);
}
void virtual_permission_free(VirtualPermissionNode* node) {
    virtual_permission_free_map(&node->childrenNode);
    dslink_map_free(&node->childrenNode);
    dslink_free(node->permissionList);
}

void virtual_permission_free_map(Map* map) {
    dslink_map_foreach(map) {
        VirtualPermissionNode* node = entry->value->data;
        virtual_permission_free(node);
    }
    dslink_map_free(map);
}

static
int get_current_permission(List *permissionList,
                        const char **groups, PermissionLevel *levels, size_t glen) {

    for (size_t g = 0; g < glen; ++g) {
        const char* group = groups[g];
        dslink_list_foreach(permissionList) {
            PermissionPair *pair = ((ListNode*)node)->value;
            if (strcmp(pair->group, group) == 0) {
                if (levels[g] < pair->permission) {
                    levels[g] = pair->permission;
                    if (pair->permission == PERMISSION_CONFIG) {
                        // config permission ignore other permission setting
                        return 1;
                    }
                }
                break;
            }
        }
    }
    return 0;
}

static
void get_virtual_permission(const char* path, VirtualPermissionNode* node,
                            const char **groups, PermissionLevel *levels, size_t glen) {
    if (node->permissionList) {
        if (get_current_permission(node->permissionList, groups, levels, glen)) {
            return;
        }
    }
    if (!path || *path == 0) {
        return;
    }

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
    if (ref && ref->data) {
        VirtualPermissionNode *child = ref->data;
        get_virtual_permission(next, child, groups, levels, glen);
    }

    if (name != path) {
        dslink_free(name);
    }

}

static
void get_node_permission(const char* path, BrokerNode* node,
                         const char **groups, PermissionLevel *levels, size_t glen) {
    if (node->permissionList) {
        if (get_current_permission(node->permissionList, groups, levels, glen)) {
            return;
        }
    }
    if (!path || *path == 0) {
        return;
    }

    const char* next = strstr(path, "/");
    char* name;
    if (next) {
        name = dslink_calloc(next - path + 1, 1);
        memcpy(name, path, next-path);
        next ++; // remove '/'
    } else {
        name = (char*)path;
    }

    if (node->type == DOWNSTREAM_NODE) {
        ref_t *ref = dslink_map_get(&((DownstreamNode *)node)->children_permissions, name);
        if (ref && ref->data) {
            VirtualPermissionNode *child = ref->data;
            get_virtual_permission(next, child, groups, levels, glen);
        }
    } else {
        ref_t *ref = dslink_map_get(node->children, name);
        if (ref && ref->data) {
            BrokerNode *child = ref->data;
            get_node_permission(next, child, groups, levels, glen);
        }
    }


    if (name != path) {
        dslink_free(name);
    }
}



PermissionLevel get_permission(const char* path, BrokerNode* rootNode, RemoteDSLink *reqLink) {
    if (!rootNode->permissionList) {
        return PERMISSION_CONFIG;
    }
    if (*path != '/') {
        return PERMISSION_NONE;
    }
    size_t glen = reqLink->permission_groups.groupLen;
    PermissionLevel *levels = dslink_calloc(glen, sizeof(PermissionLevel));
    get_node_permission(path+1, rootNode, reqLink->permission_groups.groups, levels, glen);
    PermissionLevel maxLevel = PERMISSION_NONE;
    for (size_t i = 0; i < glen; ++i) {
        if (levels[i] > maxLevel) {
            maxLevel = levels[i];
        }
    }
    dslink_free(levels);
    return maxLevel;
}
