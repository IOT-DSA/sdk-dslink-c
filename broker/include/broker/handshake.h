#ifndef BROKER_HANDSHAKE_H
#define BROKER_HANDSHAKE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/broker.h"
#include "broker/net/server.h"

json_t *broker_handshake_handle_conn(Broker *broker,
                                     const char *dsId,
                                     const char *token,
                                     json_t *handshake);
int broker_handshake_handle_ws(Broker *broker,
                               Client *client,
                               const char *dsId,
                               const char *auth,
                               const char *wsAccept);

DownstreamNode *broker_init_downstream_node(BrokerNode *parentNode, const char *name);

void dslink_handle_ping(uv_timer_t* handle);

#ifdef __cplusplus
}
#endif

#endif // BROKER_HANDSHAKE_H
