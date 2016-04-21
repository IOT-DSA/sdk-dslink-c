#ifndef BROKER_UTILS_H
#define BROKER_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"

void broker_free_handle(uv_handle_t *handle);
void broker_utils_send_closed_resp(RemoteDSLink *link,
                                   json_t *req, const char* errorType);

void broker_utils_send_static_list_resp(RemoteDSLink *link, json_t *req);

void broker_utils_send_disconnected_list_resp(RemoteDSLink *link, json_t *req);

#ifdef __cplusplus
}
#endif

#endif // BROKER_UTILS_H
