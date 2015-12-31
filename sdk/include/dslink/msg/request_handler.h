#ifndef SDK_DSLINK_C_REQUEST_HANDLER_H
#define SDK_DSLINK_C_REQUEST_HANDLER_H

#include <jansson.h>
#include "dslink/dslink.h"

#ifdef __cplusplus
extern "C" {
#endif

int dslink_request_handle(DSLink *link, json_t *req);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_REQUEST_HANDLER_H
