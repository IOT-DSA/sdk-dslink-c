#ifndef BROKER_BROKER_H
#define BROKER_BROKER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>

#include <dslink/storage/storage.h>
#include <dslink/socket.h>

#include <broker/node.h>

struct uv_loop_t;

typedef struct Broker {
    StorageProvider *storage;

    BrokerNode *root;

    BrokerNode *sys;

    BrokerNode *downstream;

    BrokerNode *upstream;

    BrokerNode *data;

    // Map<char *name, RemoteDSLink *>
    Map client_connecting;

    // Map<char *dslinkPath, List<SubRequester *> *>
    Map remote_pending_sub;

    // Map<char *path, List<SubRequester *> *>
    Map local_pending_sub;

    uv_timer_t *saveConnsHandler;

    uv_timer_t *saveDataHandler;
} Broker;

extern uv_loop_t *mainLoop;

int broker_start();
void broker_close_link(RemoteDSLink *link);
void broker_stop(Broker* broker);

void broker_on_data_callback(Client *client, void *data);

#ifdef __cplusplus
}
#endif

#endif // BROKER_BROKER_H
