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

    BrokerNode *data;

    // Map<char *name, RemoteDSLink *>
    Map client_connecting;

    // Map<char *dslinkName, List<PendingSub *> *>
    Map remote_pending_sub;

} Broker;

int broker_start();
void broker_close_link(RemoteDSLink *link);

#ifdef __cplusplus
}
#endif

#endif // BROKER_BROKER_H
