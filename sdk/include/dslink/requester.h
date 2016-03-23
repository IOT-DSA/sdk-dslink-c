#ifndef SDK_DSLINK_C_REQUESTER_H
#define SDK_DSLINK_C_REQUESTER_H

#include "dslink/dslink.h"

typedef void (*request_handler_cb)(struct DSLink *link, json_t *resp);

typedef struct RequestHolder {
    uint32_t rid;
    request_handler_cb cb;
    request_handler_cb close_cb;
} RequestHolder;

ref_t* dslink_requester_list(DSLink *link, const char* path, request_handler_cb cb);
ref_t* dslink_requester_subscribe(DSLink* link, const char* path, request_handler_cb cb);
int dslink_requester_close(DSLink *link, uint32_t rid);

#endif //SDK_DSLINK_C_REQUESTER_H
