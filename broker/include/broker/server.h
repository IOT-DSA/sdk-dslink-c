#ifndef SDK_DSLINK_C_SERVER_H
#define SDK_DSLINK_C_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>

#include <dslink/socket.h>
#include "broker/http.h"

typedef void (*HttpCallback)(HttpRequest *req, Socket *sock);

int dslink_broker_start_server(json_t *config, HttpCallback cb);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_SERVER_H
