#ifndef BROKER_NET_SERVER_H
#define BROKER_NET_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <uv.h>
#include <jansson.h>
#include <dslink/socket.h>

#include "broker/net/http.h"

typedef struct Server Server;

typedef struct Client {
    Server *server;
    Socket *sock;
    void *sock_data;
    uv_poll_t *poll;
} Client;

typedef void (*DataReadyCallback)(Client *client,
                                  void *data);

typedef void (*ClientErrorCallback)(void *socketData);

int broker_start_server(json_t *config);

#ifdef __cplusplus
}
#endif

#endif // BROKER_NET_SERVER_H
