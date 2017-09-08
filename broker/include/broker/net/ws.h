#ifndef BROKER_NET_WS_H
#define BROKER_NET_WS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <jansson.h>
#include "broker/remote_dslink.h"


void broker_ws_send_init(Socket *sock, const char *accept);
int broker_ws_send_obj(RemoteDSLink *link, json_t *obj);
int broker_ws_send_obj_link_id(struct Broker* broker, const char *link_name, int upstream, json_t *obj);
int broker_ws_send(RemoteDSLink *link, const char *data);
int broker_ws_generate_accept_key(const char *buf, size_t bufLen,
                                  char *out, size_t outLen);
int broker_count_json_msg(json_t *json);

#ifdef BROKER_WS_SEND_THREAD_MODE
void broker_send_ws_thread(void *arg);
#endif

#ifdef __cplusplus
}
#endif

#endif // BROKER_NET_WS_H
