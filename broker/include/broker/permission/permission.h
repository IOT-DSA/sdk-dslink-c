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
struct VirtualDownstreamNode;

// numbers in the PermissionLevel doesn't matter
// it should always be serialized as string
typedef enum {PERMISSION_NONE = 0,
    PERMISSION_LIST = 1,
    PERMISSION_READ = 2,
    PERMISSION_WRITE = 3,
    PERMISSION_CONFIG = 4,
    PERMISSION_NEVER = 5} PermissionLevel;

extern const char* PERMISSION_NAMES[6];

const char *permission_level_str(PermissionLevel level);
PermissionLevel permission_str_level(const char *str);

// a list of requester permission groups
typedef struct PermissionGroups {
    const char **groups;
    size_t groupLen;
} PermissionGroups;

typedef struct PermissionPair {
    char *group;
    PermissionLevel permission;
} PermissionPair;

void permission_groups_init(PermissionGroups* groups);
void permission_groups_free(PermissionGroups* groups);
void permission_groups_load(PermissionGroups* groups, const char *dsId, const char* str);

// permission list for node or virtual node
void permission_list_free(List* list);
json_t *permission_list_save(List * permissionList);
List *permission_list_load(json_t *json);


PermissionLevel get_permission(const char* path, struct BrokerNode* rootNode, struct RemoteDSLink *reqLink);

uint8_t set_permission(const char* path, struct BrokerNode* rootNode, struct RemoteDSLink *reqLink, json_t *json);

#ifdef __cplusplus
}
#endif

#endif //BROKER_PERMISSION_H
