#ifndef BROKER_NET_WS_H
#define BROKER_NET_WS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "broker/remote_dslink.h"

int broker_ws_send_obj(RemoteDSLink *link, json_t *obj);
int broker_ws_send(RemoteDSLink *link, const char *data);


#ifdef __cplusplus
}
#endif

#endif // BROKER_NET_WS_H
