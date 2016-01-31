#ifndef BROKER_BROKER_H
#define BROKER_BROKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>
#include <dslink/col/map.h>
#include <dslink/socket.h>

#include "broker/remote_dslink.h"
#include "broker/node.h"

typedef struct Broker {

    BrokerNode *root;

    // Map<char *name, RemoteDSLink *>
    BrokerNode *downstream;

    // Map<char *name, RemoteDSLink *>
    Map client_connecting;

} Broker;

int broker_start();

void broker_send_ws_init(Socket *sock, const char *accept);

#ifdef __cplusplus
}
#endif

#endif // BROKER_BROKER_H
