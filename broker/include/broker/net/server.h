#ifndef BROKER_NET_SERVER_H
#define BROKER_NET_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>

#include <dslink/socket.h>
#include "broker/net/http.h"

typedef void (*DataReadyCallback)(Socket *sock,
                                  void *data,
                                  void **socketData);

typedef void (*ClientErrorCallback)(void *socketData);

int broker_start_server(json_t *config,
                        void *data,
                        DataReadyCallback drc,
                        ClientErrorCallback cec);

#ifdef __cplusplus
}
#endif

#endif // BROKER_NET_SERVER_H
