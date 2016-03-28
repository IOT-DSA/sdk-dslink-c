//
// Created by rinick on 16/03/16.
//

#ifndef BROKER_PERMISSION_H
#define BROKER_PERMISSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include <dslink/col/list.h>
#include <dslink/col/map.h>

struct RemoteDSLink;
struct BrokerNode;
struct json_t;

// numbers in the PermissionLevel doesn't matter
// it should always be serialized as string
typedef enum {PERMISSION_NONE = 0,
    PERMISSION_LIST = 1,
    PERMISSION_READ = 2,
    PERMISSION_WRITE = 3,
    PERMISSION_CONFIG = 4,
    PERMISSION_NEVER = 5} PermissionLevel;

extern const char* PERMISSION_NAMES[6];

// a list of requester permission groups
typedef struct PermissionGroups {
    const char **groups;
    size_t groupLen;
} PermissionGroups;

typedef struct PermissionPair {
    char *group;
    PermissionLevel permission;
} PermissionPair;

// virtual permission node for downstream nodes
typedef struct VirtualPermissionNode {
    List *permissionList;
    Map childrenNode;
} VirtualPermissionNode;

void permission_groups_init(PermissionGroups* groups);
void permission_groups_free(PermissionGroups* groups);

void virtual_permission_init(VirtualPermissionNode* node);
void virtual_permission_free(VirtualPermissionNode* node);
// free a children map of virtual permissions
void virtual_permission_free_map(Map* map);

// permission list for node or virtual node
json_t *permission_list_save(List * permissionList);
List *permission_list_load(json_t *json);


PermissionLevel get_permission(const char* path, struct BrokerNode* rootNode, struct RemoteDSLink *reqLink);

#ifdef __cplusplus
}
#endif

#endif //BROKER_PERMISSION_H
