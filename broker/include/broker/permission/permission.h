//
// Created by rinick on 16/03/16.
//

#ifndef BROKER_PERMISSION_H
#define BROKER_PERMISSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/col/list.h>

typedef struct PermissionPair {
    char *group;
    int permission;
} PermissionPair;


int get_permission(List* permissionList, char **groups);

#ifdef __cplusplus
}
#endif

#endif //BROKER_PERMISSION_H
