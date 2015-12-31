#ifndef SDK_DSLINK_C_LIST_RESPONSE_H
#define SDK_DSLINK_C_LIST_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "dslink/dslink.h"

int dslink_response_list(DSLink *link, json_t *req, DSNode *node);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_LIST_RESPONSE_H
