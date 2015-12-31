#ifndef SDK_DSLINK_C_SUB_H
#define SDK_DSLINK_C_SUB_H

#ifdef __cplusplus
extern "C" {
#endif

#include "node.h"

typedef enum StreamType {
    INVALID_STREAM = 0,
    LIST_STREAM
} StreamType;

typedef struct Stream {
    StreamType type;
    const char *path;
    node_event_cb on_close;
} Stream;

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_SUB_H
