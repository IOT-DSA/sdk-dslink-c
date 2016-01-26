#ifndef BROKER_HANDSHAKE_H
#define BROKER_HANDSHAKE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/broker.h"

json_t *broker_handshake_handle_conn(Broker *broker,
                                     const char *dsId,
                                     json_t *handshake);
int broker_handshake_handle_ws(Broker *broker,
                               const char *dsId,
                               const char *auth,
                               void **socketData);

#ifdef __cplusplus
}
#endif

#endif // BROKER_HANDSHAKE_H
