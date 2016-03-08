#ifndef BROKER_MSG_UNSUBSCRIBE_H
#define BROKER_MSG_UNSUBSCRIBE_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"
#include "broker/stream.h"

void broker_msg_send_unsubscribe(BrokerSubStream *bss, RemoteDSLink *link);
int broker_msg_handle_unsubscribe(RemoteDSLink *link, json_t *req);

#ifdef __cplusplus
}
#endif

#endif // BROKER_MSG_UNSUBSCRIBE_H
