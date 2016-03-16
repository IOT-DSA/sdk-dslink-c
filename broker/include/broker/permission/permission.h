//
// Created by rinick on 16/03/16.
//

#ifndef BROKER_PERMISSION_H
#define BROKER_PERMISSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/col/list.h>
#include <dslink/col/map.h>

struct RemoteDSLink;
struct BrokerNode;
struct json_t;

typedef enum {PERMISSION_NONE = 0,
    PERMISSION_LIST = 10,
    PERMISSION_READ = 20,
    PERMISSION_WRITE = 30,
    PERMISSION_CONFIG = 40,
    PERMISSION_NEVER = 127} PermissionLevel;

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
void virtual_permission_free_map(Map* map);

PermissionLevel get_permission(const char* path, struct BrokerNode* rootNode, struct RemoteDSLink *reqLink);

#ifdef __cplusplus
}
#endif

#endif //BROKER_PERMISSION_H
