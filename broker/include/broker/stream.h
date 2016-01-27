#ifndef BROKER_STREAM_H
#define BROKER_STREAM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <dslink/col/map.h>

typedef enum StreamType {

    LIST

} StreamType;

typedef struct Stream {

    StreamType type;

} Stream;

typedef struct ListStream {

    StreamType type;

    // Map<uint32_t *, RemoteDSLink *>
    Map clients;

} ListStream;

#ifdef __cplusplus
}
#endif

#endif // BROKER_STREAM_H
