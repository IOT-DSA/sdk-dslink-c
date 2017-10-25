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
typedef enum {
    PERMISSION_NONE = 0,
    PERMISSION_LIST = 1,
    PERMISSION_READ = 2,
    PERMISSION_WRITE = 3,
    PERMISSION_CONFIG = 4,
    PERMISSION_NEVER = 5} PermissionLevel;

extern const char* PERMISSION_NAMES[6];

const char *permission_level_str(PermissionLevel level);
PermissionLevel permission_str_level(const char *str);


typedef struct PermissionPair {
    char *group;
    PermissionLevel permission;
} PermissionPair;



void filter_list_according_to_permission(json_t *l, PermissionLevel level);


PermissionLevel get_permission(const char* path, struct BrokerNode* rootNode, struct RemoteDSLink *reqLink);

uint8_t set_permission_list(const char *path, struct BrokerNode *rootNode, struct RemoteDSLink *reqLink, json_t *json);
json_t *get_permission_list(const char* path, struct BrokerNode* rootNode, struct RemoteDSLink *reqLink);


// permission list for node or virtual node
void permission_list_free(List* list);
json_t *permission_list_get_as_json(List *permissionList);
List *permission_list_new_from_json(json_t *json);


int security_barrier(struct RemoteDSLink *link, json_t *req,
                     const char *path, PermissionLevel allowed_level,
                     PermissionLevel* permission);


#ifdef __cplusplus
}
#endif

#endif //BROKER_PERMISSION_H
