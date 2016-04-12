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
    UPSTREAM_CONN_CHECK,
    UPSTREAM_WS
} UpstreamPollStatus;

typedef struct UpstreamPoll {
    UpstreamPollStatus status;
    uv_poll_t *connPoll;
    uv_timer_t *connCheckTimer;
    uint32_t connCheckCount;
    struct addrinfo *conCheckAddrList;
    uv_poll_t *wsPoll;
    char *brokerUrl;
    char *dsId;
    char *name;
    char *idPrefix;
    char *group;
    uint32_t reconnectInterval;
    uv_timer_t * reconnectTimer;
    struct DownstreamNode *node;
    struct RemoteDSLink * remoteDSLink;
    struct DSLink *clientDslink;
    struct Socket *sock;
    struct wslay_event_context *ws; // Event context for WSLay
} UpstreamPoll;

void upstream_create_poll(const char *brokerUrl, const char *name, const char *idPrefix, const char *group);

void upstream_connect_conn(UpstreamPoll *upstreamPoll);

void upstream_clear_poll(UpstreamPoll *upstreamPoll);

void upstream_connect_ws();

// disconnected from network
void upstream_disconnected();

// disconnect upstream when it's no longer needed
void upstream_disconnect();

void init_upstream_link(struct Broker *broker, UpstreamPoll *upstreamPoll);


int dslink_socket_connect_async(UpstreamPoll *upstreamPoll,
                                const char *address,
                                unsigned short port,
                                uint_fast8_t secure);
int connectConnCheck(UpstreamPoll *upstreamPoll);

#ifdef __cplusplus
}
#endif

#endif //BROKER_UPSTREAM_HANDSHAKE_H
