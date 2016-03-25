#ifndef BROKER_UPSTREAM_HANDSHAKE_H
#define BROKER_UPSTREAM_HANDSHAKE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <uv.h>
#include <wslay/wslay.h>
#include <wslay_event.h>

struct DSLink;
struct Socket;
struct Broker;
struct wslay_event_context;


typedef enum UpstreamPollStatus {
    UPSTREAM_NONE = 0,
    UPSTREAM_CONN,
    UPSTREAM_WS
} UpstreamPollStatus;

typedef struct UpstreamPoll {
    UpstreamPollStatus status;
    uv_poll_t connPoll;
    uv_poll_t wsPoll;
    char *dsId;
    char *name;
    char *idPrefix;
    struct RemoteDSLink * remoteDSLink;
    struct DSLink *clientDslink;
    struct Socket *sock;
    struct wslay_event_context *ws; // Event context for WSLay
} UpstreamPoll;

void upstream_create_poll(uv_loop_t *loop, const char *brokerUrl, const char *name, const char *idPrefix);

void upstream_connect_conn(UpstreamPoll *upstreamPoll,  const char *brokerUrl);

void upstream_connect_ws();

// disconnected from network
void upstream_disconnected();

// disconnect upstream when it's no longer needed
void upstream_disconnect();

void init_upstream_link(struct Broker *broker, UpstreamPoll *upstreamPoll);

#ifdef __cplusplus
}
#endif

#endif //BROKER_UPSTREAM_HANDSHAKE_H
