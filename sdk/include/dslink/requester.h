#ifndef SDK_DSLINK_C_REQUESTER_H
#define SDK_DSLINK_C_REQUESTER_H

#include "dslink/dslink.h"

typedef void (*request_handler_cb)(struct DSLink *link, json_t *resp);
typedef void (*value_sub_cb)(struct DSLink *link, uint32_t sid, json_t *val, json_t *ts);

typedef struct RequestHolder {
    uint32_t rid;
    uint32_t sid;
    request_handler_cb cb;
    request_handler_cb close_cb;
} RequestHolder;

typedef struct SubscribeCallbackHolder {
    value_sub_cb cb;
} SubscribeCallbackHolder;

/*
 * List a node. Returns a ref_t of the RequestHolder for this request.
 */
ref_t* dslink_requester_list(DSLink *link, const char* path, request_handler_cb cb);
ref_t* dslink_requester_subscribe(DSLink* link, const char* path, value_sub_cb cbs);
ref_t* dslink_requester_unsubscribe(DSLink* link, uint32_t sid);
ref_t* dslink_requester_set(DSLink* link, const char* path, json_t *value);
ref_t* dslink_requester_remove(DSLink* link, const char* path);
int dslink_requester_close(DSLink *link, uint32_t rid);

#endif //SDK_DSLINK_C_REQUESTER_H
