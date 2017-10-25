#ifndef SDK_DSLINK_C_WS_H
#define SDK_DSLINK_C_WS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wslay/wslay.h>
#include <wslay_event.h>

#include <jansson.h>
#include <msgpack.h>

#include "dslink/dslink.h"
#include "dslink/socket.h"
#include "dslink/err.h"
#include "dslink/url.h"

int dslink_handshake_connect_ws(Url *url,
                                dslink_ecdh_context *key,
                                const char *uri,
                                const char *tempKey,
                                const char *salt,
                                const char *dsId,
                                const char *token,
                                const char *format,
                                Socket **sock);

void dslink_handshake_handle_ws(DSLink *link, link_callback on_requester_ready_cb);

int dslink_ws_send(struct wslay_event_context* ctx, struct wslay_event_msg msg);

int dslink_ws_send_obj(struct wslay_event_context *ctx, json_t *obj);

struct wslay_event_msg dslink_ws_dump_json_into_msg(json_t *obj, int as_msgpack);


#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_WS_H
