#ifndef SDK_DSLINK_C_SUB_RESPONSE_H
#define SDK_DSLINK_C_SUB_RESPONSE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "dslink/dslink.h"

int dslink_response_sub(DSLink *link, json_t *paths, json_t *rid);
int dslink_response_unsub(DSLink *link, json_t *sids, json_t *rid);

void dslink_response_send_val(DSLink *link,
                              DSNode *node,
                              uint32_t sid);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_SUB_RESPONSE_H
