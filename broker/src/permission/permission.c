
#include "broker/permission/permission.h"
#include <broker/node.h>
#include <broker/remote_dslink.h>
#include <string.h>
#include <dslink/utils.h>
#include <broker/broker.h>

const char* PERMISSION_NAMES[6] = {"none", "list", "read", "write", "config", "never"};

const char *permission_level_str(PermissionLevel level) {
    if (level >= PERMISSION_NONE && level <= PERMISSION_NEVER) {
        return PERMISSION_NAMES[level];
    }
    return "none";
}
PermissionLevel permission_str_level(const char *str) {
    if (!str) {
        return PERMISSION_NEVER;
    }
    PermissionLevel p = PERMISSION_NONE;
    for (; p <= PERMISSION_CONFIG; ++p) {
        if (strcmp(str, PERMISSION_NAMES[p]) == 0) {
            break;
        }
    }
    return p;
}


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



void permission_groups_load(PermissionGroups* groups, const char *dsId, const char* str) {
    if (groups->groups) {
        permission_groups_free(groups);
    }
    size_t allocatedLen = 1;
    size_t len = 0;

    if (str) {
        allocatedLen = 4;
        groups->groups = dslink_malloc(sizeof(char*) * allocatedLen);

        const char *start = str;
        const char *end = str - 1;

        do {
            ++end;
            if (*end == ',' || *end == '\0')  {
                if (end > start) {
                    // +1 for current value, +1 for the dsId
                    if (len + 2 > allocatedLen) {
                        allocatedLen *= 2;
                        groups->groups = dslink_realloc(groups->groups, sizeof(char*) * allocatedLen);
                    }
                    groups->groups[len] = dslink_strdupl(start, end - start);
                    ++len;
                }
                start = end + 1;
            }
        }while (*end);
    } else {
        groups->groups = dslink_malloc(sizeof(char*));
    }

    // dsId as a permission group
    groups->groups[len] = dslink_strdup(dsId);
    ++len;

    groups->groupLen = len;
}

static
int get_current_permission(List *permissionList,
                        const char **groups, PermissionLevel *levels, size_t glen) {

    for (size_t g = 0; g < glen; ++g) {
        const char* group = groups[g];
        dslink_list_foreach(permissionList) {
            PermissionPair *pair = ((ListNode*)node)->value;
            if (strcmp(pair->group, group) == 0 || strcmp(pair->group, "default") == 0 ) {
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
void get_virtual_permission(const char* path, VirtualDownstreamNode* node,
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
        VirtualDownstreamNode *child = ref->data;
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
            VirtualDownstreamNode *child = ref->data;
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


static
uint8_t set_virtual_permission(const char* path, VirtualDownstreamNode* node, json_t *json) {
    if (!path || *path == 0) {
        List *permissions = permission_list_load(json);
        permission_list_free(node->permissionList);
        node->permissionList = permissions;
        return 0;
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
            child = dslink_calloc(1, sizeof(VirtualDownstreamNode));
            virtual_downstream_node_init(child);
            dslink_map_set(&node->childrenNode, dslink_str_ref(name), dslink_ref(child, NULL));
        }
        return set_virtual_permission(next, child, json);
    }
}

static
uint8_t set_node_permission(const char* path, BrokerNode* node, json_t *json) {
    if (!path || *path == 0) {
        List *permissions = permission_list_load(json);
        permission_list_free(node->permissionList);
        node->permissionList = permissions;
        return 0;
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
        if (node->type == DOWNSTREAM_NODE) {
            ref_t *ref = dslink_map_get(&((DownstreamNode *)node)->children_permissions, name);
            VirtualDownstreamNode *child;
            if (ref && ref->data) {
                child = ref->data;
            } else {
                child = dslink_calloc(1, sizeof(VirtualDownstreamNode));
                virtual_downstream_node_init(child);
                dslink_map_set(&((DownstreamNode *)node)->children_permissions, dslink_str_ref(name), dslink_ref(child, NULL));
            }
            return set_virtual_permission(next, child, json);
        } else {
            ref_t *ref = dslink_map_get(node->children, name);
            if (ref && ref->data) {
                BrokerNode *child = ref->data;
                return set_node_permission(next, child, json);
            } else {
                return 1;
            }
        }
    }
}

uint8_t set_permission(const char* path, struct BrokerNode* rootNode, struct RemoteDSLink *reqLink, json_t *json) {
    if (!json_is_array(json)) {
        return 1;
    }
    PermissionLevel level = get_permission(path, rootNode, reqLink);
    if (level != PERMISSION_CONFIG) {
        return 1;
    }
    uint8_t rslt = set_node_permission(path+1, rootNode, json);
    if (rslt == 0) {
        Broker *broker = mainLoop->data;
        if (dslink_str_starts_with(path, "/data/")) {
            broker_data_nodes_changed(broker);
        } else if (dslink_str_starts_with(path, "/downstream/")) {
            broker_downstream_nodes_changed(broker);
        }
    }

    return rslt;
}


// permission list for node or virtual node
void permission_list_free(List* list) {
    if (!list) {
        return;
    }
    dslink_list_foreach(list) {
        PermissionPair * pair = ((ListNode*)node)->value;
        dslink_free(pair->group);
        dslink_free(pair);
    }
    dslink_list_free(list);
}

json_t *permission_list_save(List * permissionList) {
    if (!permissionList || list_is_empty(permissionList)) {
        return NULL;
    }
    json_t *rslt = json_array();
    dslink_list_foreach(permissionList) {
        PermissionPair *p = ((ListNode*)node)->value;
        if (p->permission < PERMISSION_NEVER) {
            json_t *pair = json_array();
            json_array_append_new(pair, json_string_nocheck(p->group));
            json_array_append_new(pair, json_string_nocheck(PERMISSION_NAMES[p->permission]));

            json_array_append_new(rslt, pair);
        }
    }
    return rslt;
}

List *permission_list_load(json_t *json) {
    if (!json_is_array(json) || json_array_size(json) == 0) {
        return NULL;
    }
    List *rslt = dslink_calloc(1, sizeof(List));
    list_init(rslt);

    size_t idx;
    json_t *value;
    json_array_foreach(json, idx, value) {
        if (json_array_size(value) == 2) {
            json_t *v0 = json_array_get(value, 0);
            json_t *v1 = json_array_get(value, 1);
            if (json_is_string(v0) && json_is_string(v1)) {
                const char* vc0 = json_string_value(v0);
                const char* vc1 = json_string_value(v1);
                PermissionLevel p = permission_str_level(vc1);
                if (p <= PERMISSION_CONFIG) {
                    PermissionPair * pair = dslink_malloc(sizeof(PermissionPair));
                    pair->group = dslink_strdup(vc0);
                    pair->permission = p;
                    dslink_list_insert(rslt, pair);
                }
            }
        }
    }
    return rslt;
}
