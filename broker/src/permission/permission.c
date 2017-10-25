
#include "broker/permission/permission.h"
#include "broker/permission/permission_group.h"
#include <broker/node.h>
#include <broker/broker.h>
#include <broker/config.h>
#include <broker/utils.h>
#include <string.h>

// PERMISSION STRINGS /////////////////////////////////////////////////
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

///////////////////////////////////////////////////////////////////////

// THIS IS ONLY TAKING UPDATE array section
void remove_entries_from_update_according_to_permission(json_t *l, PermissionLevel level)
{
    (void) level;

    json_t *main_value = NULL;

    unsigned int i = 0;

    json_array_foreach(l, i, main_value)
    {
        if(!json_is_array(main_value))
            continue;

        // It is nodes value itself check it
        json_t* maybe_writable = json_array_get(main_value,0);
        if(maybe_writable && strcmp("$writable", json_string_value(maybe_writable)) == 0)
        {
            json_t* writable_perm = json_array_get(main_value,1);
            if(writable_perm && permission_str_level(json_string_value(writable_perm)) > level)
            {
                json_array_remove(l, i);
                i--;
                continue;
            }
        }

        json_t* props = json_array_get(main_value, 1);
        if(!props) continue;

        // Find in probs
        json_t* invokable = json_object_get(props, "$invokable");

        if(invokable && permission_str_level(json_string_value(invokable)) > level)
        {
            json_array_remove(l, i);
            i--;
            continue;
        }

        json_t* writable = json_object_get(props, "$writable");
        if(writable && permission_str_level(json_string_value(invokable)) > level)
        {
            json_object_del(props, "$writable");
            continue;
        }
    }
}

// Finding name "update" in all json sending to remove
void filter_list_according_to_permission(json_t *l, PermissionLevel level)
{
    if(level == PERMISSION_CONFIG) return;

    const char *main_key = NULL;
    json_t *main_value = NULL;
    unsigned int i = 0;

    if(json_is_array(l))
    {
        json_array_foreach(l, i, main_value)
        {
            filter_list_according_to_permission(main_value, level);
        }
    }

    if(json_is_object(l))
    {
        json_object_foreach(l, main_key, main_value) {

            if(main_key == NULL)
                continue;

            if(strcmp(main_key, "updates") == 0){
                remove_entries_from_update_according_to_permission(main_value, level);
            }
            else {
                filter_list_according_to_permission(main_value, level);
            }
        }
    }


}


// For every group that node have
// Travel all the groups and
// select the highest permission in the group
static
int fill_permission_levels(List *permissionList, const char **groups,
                           PermissionLevel *levels, size_t glen) {

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
                //break; //this break blocks checking permission pairs after default
            }
        }
    }
    return 0;
}

static
void get_virtual_permission(const char* path, VirtualDownstreamNode* node,
                            const char **groups, PermissionLevel *levels, size_t glen) {
    if (node->permissionList) {
        if (fill_permission_levels(node->permissionList, groups, levels, glen)) {
            return;
        }
    }

    if (!path || *path == 0) {
        return;
    }

    // We couldn't find any permission here
    // so we are going to next level

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
        if (fill_permission_levels(node->permissionList, groups, levels, glen)) {
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

    // Getting maximum level from permission level list
    PermissionLevel maxLevel = PERMISSION_NONE;
    for (size_t i = 0; i < glen; ++i) {
        if (levels[i] > maxLevel) {
            maxLevel = levels[i];
        }
    }
    dslink_free(levels);

    return maxLevel;
}


static uint8_t set_virtual_permission_list(const char* path, VirtualDownstreamNode* node, json_t *json) {
    if (!path || *path == 0) {
        List *permissions = permission_list_new_from_json(json);
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
        return set_virtual_permission_list(next, child, json);
    }
}

static uint8_t set_node_permission_list(const char* path, BrokerNode* node, json_t *json) {
    if (!path || *path == 0) {
        List *permissions = permission_list_new_from_json(json);
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
            return set_virtual_permission_list(next, child, json);
        } else {
            ref_t *ref = dslink_map_get(node->children, name);
            if (ref && ref->data) {
                BrokerNode *child = ref->data;
                return set_node_permission_list(next, child, json);
            } else {
                return 1;
            }
        }
    }
}

uint8_t set_permission_list(const char *path, struct BrokerNode *rootNode, struct RemoteDSLink *reqLink, json_t *json) {
    if (!json_is_array(json)) {
        return 1;
    }
    PermissionLevel level = get_permission(path, rootNode, reqLink);
    if (level != PERMISSION_CONFIG) {
        return 1;
    }
    uint8_t rslt = set_node_permission_list(path+1, rootNode, json);
    if (rslt == 0) {
        Broker *broker = mainLoop->data;
        if (strcmp(path, "/") == 0) {
            broker_change_default_permissions(json);
        } else if (dslink_str_starts_with(path, "/data/")) {
            broker_data_nodes_changed(broker);
        } else if (dslink_str_starts_with(path, "/downstream/")) {
            broker_downstream_nodes_changed(broker);
        }
    }

    return rslt;
}


static json_t *get_virtual_permission_list(const char* path, VirtualDownstreamNode* node) {
    if (!path || *path == 0) {
        return permission_list_get_as_json(node->permissionList);
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
        return get_virtual_permission_list(next, child);
    }
}

static json_t *get_node_permission_list(const char* path, BrokerNode* node) {
    if (!path || *path == 0) {
        return permission_list_get_as_json(node->permissionList);
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
            return get_virtual_permission_list(next, child);
        } else {
            ref_t *ref = dslink_map_get(node->children, name);
            if (ref && ref->data) {
                BrokerNode *child = ref->data;
                return get_node_permission_list(next, child);
            } else {
                return NULL;
            }
        }
    }
}

json_t * get_permission_list(const char* path, struct BrokerNode* rootNode, struct RemoteDSLink *reqLink) {

    PermissionLevel level = get_permission(path, rootNode, reqLink);
    if (level < PERMISSION_READ) {
        return NULL;
    }
    return get_node_permission_list(path+1, rootNode);
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

json_t *permission_list_get_as_json(List *permissionList) {
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

List *permission_list_new_from_json(json_t *json) {
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

int security_barrier(struct RemoteDSLink *requester,
                     json_t *req, const char *path,
                     PermissionLevel allowed_level_on_root,
                     PermissionLevel* requester_level_out)
{
    // Checking the permit on request
    // It can allow the maximum permission
    json_t *maxPermitJson = NULL;
    if(req) maxPermitJson = json_object_get(req, "permit");

    PermissionLevel maxPermit = PERMISSION_CONFIG;
    if (maxPermitJson && json_is_string(maxPermitJson)) {
        maxPermit = permission_str_level(json_string_value(maxPermitJson));
    }

    // get permission from requester's broker's root
    PermissionLevel requester_level;
    requester_level = get_permission(path, requester->broker->root, requester);

    // Check if requester want to access to the another node permission
    char *out = NULL;
    BrokerNode *node_on_path = broker_node_get(requester->broker->root, path, &out);

    if(node_on_path && node_on_path->type == DOWNSTREAM_NODE)
    {
        DownstreamNode *dsn = (DownstreamNode *) node_on_path;

        if(dsn->link)
        {
            // We are checking the permission of the requested link on broker,
            // If it is bigger than requester permission we will not serve anything!
            PermissionLevel on_path_permission = get_permission("/", requester->broker->root, dsn->link);

            if(on_path_permission>requester_level)
                requester_level = PERMISSION_NONE;
        }
    }

    // clamping it to maxpermit,
    if (requester_level > maxPermit) {
        requester_level = maxPermit;
    }

    if(requester_level_out) *requester_level_out = requester_level;

    // Check if its a for /sys
    // For permission it is not allowed!
    if(strlen(path) > 3)
    {
        if( dslink_str_starts_with(path, "/sys") && requester_level < PERMISSION_CONFIG)
        {
            if(req) broker_utils_send_closed_resp(requester, req, "permissionDenied");
            return 0;
        }
    }

    // Checking the permission finally
    if (requester_level < allowed_level_on_root) {
        if(req) broker_utils_send_closed_resp(requester, req, "permissionDenied");
        return 0;
    }

    return 1;
}