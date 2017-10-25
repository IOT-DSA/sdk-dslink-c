//
// Created by mk on 10/21/17.
//

#include "broker/permission/permission_group.h"


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
        groups->groups = NULL;
    }
}

void permission_groups_load(PermissionGroups* groups, const char *dsId, const char* str) {
    if (groups->groups) {
        permission_groups_free(groups);
    }

    // FIRST COUNT!
    size_t alloc_len = 0;
    if (str) {
        const char *start = str;
        const char *end = str - 1;
        do {
            ++end;
            if (*end == ',' || *end == '\0')  {
                if (end > start) {
                    ++alloc_len;
                }
                start = end + 1;
            }
        }while (*end);
    }

    if(dsId) {
        ++alloc_len;
    }

    groups->groups = dslink_malloc(sizeof(char*) * alloc_len);

    // ASSIGN!
    size_t len = 0;

    if (str) {
        const char *start = str;
        const char *end = str - 1;

        do {
            ++end;
            if (*end == ',' || *end == '\0')  {
                if (end > start) {
                    groups->groups[len] = dslink_strdupl(start, end - start);
                    ++len;
                }
                start = end + 1;
            }
        }while (*end);
    }

    // dsId as a permission group
    if(dsId) {
        groups->groups[len] = dslink_strdup(dsId);
        ++len;
    }

    groups->groupLen = len;
}

