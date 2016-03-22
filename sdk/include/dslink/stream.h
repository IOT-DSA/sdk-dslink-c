#ifndef SDK_DSLINK_C_STREAM_H
#define SDK_DSLINK_C_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include "node.h"

typedef enum StreamType {
    INVALID_STREAM = 0,
    LIST_STREAM,
    INVOCATION_STREAM,
    SUBSCRIPTION_STREAM
} StreamType;

typedef struct Stream {
    StreamType type;
    const char *path;
    dslink_stream_close_cb on_close;
    int unused;
    void *data;
} Stream;

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_STREAM_H
