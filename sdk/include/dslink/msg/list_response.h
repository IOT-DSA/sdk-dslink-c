#ifndef SDK_DSLINK_C_LIST_RESPONSE_H
#define SDK_DSLINK_C_LIST_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "dslink/dslink.h"

int dslink_response_list(DSLink *link, json_t *req, DSNode *node);

int dslink_response_list_append_child(json_t *update, DSNode *child);
void dslink_response_list_append_meta(json_t *obj, Map *meta, const char *name);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_LIST_RESPONSE_H
