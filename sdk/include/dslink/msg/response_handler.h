#ifndef SDK_DSLINK_C_RESPONSE_HANDLER_H
#define SDK_DSLINK_C_RESPONSE_HANDLER_H

#include <jansson.h>
#include "dslink/dslink.h"

#ifdef __cplusplus
extern "C" {
#endif

int dslink_response_handle(DSLink *link, json_t *resp);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_RESPONSE_HANDLER_H
