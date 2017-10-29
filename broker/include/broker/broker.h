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

    // Map<char *name, RemoteDSLink *>
    Map remote_connected;

    // Map<char *dslinkPath, List<SubRequester *> *>
    Map remote_pending_sub;

    // Map<char *path, List<SubRequester *> *>
    Map local_pending_sub;

    uv_timer_t *saveConnsHandler;

    uv_timer_t *saveDataHandler;

#ifdef BROKER_WS_SEND_THREAD_MODE
    uv_sem_t ws_send_sem;
    uv_sem_t ws_queue_sem;
    int closing_send_thread;
    uv_thread_t ws_send_thread_id;
    RemoteDSLink *currLink;
#endif

#ifdef BROKER_PING_THREAD
    uv_thread_t ping_thread_id;
    int closing_ping_thread;
#endif

    struct UpstreamPoll **pendingActionUpstreamPoll;

} Broker;

extern uv_loop_t *mainLoop;

int broker_start();
void _broker_close_link(RemoteDSLink *link);
void broker_close_link(RemoteDSLink *link);
void broker_destroy_link(RemoteDSLink *link);
void broker_stop(Broker* broker);

void broker_on_data_callback(Client *client, void *data);

#ifdef __cplusplus
}
#endif

#endif // BROKER_BROKER_H
