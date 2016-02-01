#ifndef BROKER_BROKER_H
#define BROKER_BROKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>
#include <dslink/socket.h>
#include "broker/node.h"

typedef struct Broker {

    BrokerNode *root;

    BrokerNode *sys;

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
