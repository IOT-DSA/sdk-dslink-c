#ifndef BROKER_NET_WS_HANDLER_H
#define BROKER_NET_WS_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

const struct wslay_event_callbacks *broker_ws_callbacks();

ssize_t broker_want_read_cb(wslay_event_context_ptr ctx,
                     uint8_t *buf, size_t len,
                     int flags, void *user_data);

ssize_t broker_want_write_cb(wslay_event_context_ptr ctx,
                      const uint8_t *data, size_t len,
                      int flags, void *user_data);
void broker_on_ws_data(wslay_event_context_ptr ctx,
                const struct wslay_event_on_msg_recv_arg *arg,
                void *user_data);

#ifdef __cplusplus
}
#endif

#endif // BROKER_NET_WS_HANDLER_H
