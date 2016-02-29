#ifndef BROKER_UTILS_H
#define BROKER_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "broker/remote_dslink.h"

void broker_utils_send_closed_resp(RemoteDSLink *link,
                                   json_t *req);

#ifdef __cplusplus
}
#endif

#endif // BROKER_UTILS_H
