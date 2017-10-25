//
// Created by mk on 10/21/17.
//

#ifndef PERMISSION_GROUP_H
#define PERMISSION_GROUP_H

#include <dslink/utils.h>
#include <dslink/mem/mem.h>


// a list of requester permission groups
typedef struct PermissionGroups {
    const char **groups;
    size_t groupLen;
} PermissionGroups;

void permission_groups_init(PermissionGroups* groups);

void permission_groups_free(PermissionGroups* groups);

void permission_groups_load(PermissionGroups* groups, const char *dsId, const char* str);





#endif //PERMISSION_GROUP_H