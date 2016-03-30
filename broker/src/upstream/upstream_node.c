#include <broker/upstream/upstream_node.h>
#include <broker/broker.h>
#include <broker/upstream/upstream_handshake.h>
#include <broker/handshake.h>
#include <broker/msg/msg_list.h>
#include <dslink/utils.h>
#include <string.h>

DownstreamNode *create_upstream_node(Broker *broker, const char *name) {
    ref_t *ref = dslink_map_get(broker->upstream->children,
                                (char *)name);
    DownstreamNode *node = NULL;
    if (!ref) {
        node = broker_init_downstream_node(broker->upstream, name);
        char buff[1024];
        strcpy(buff, "/upstream/");
        strcpy(buff + sizeof("/upstream/") -1 , name);
        node->path = dslink_strdup(buff);
        if (broker->upstream->list_stream) {
            update_list_child(broker->upstream,
                              broker->upstream->list_stream,
                              name);
        }
    } else {
        node = ref->data;
    }
    return node;
}

void init_upstream_node(Broker *broker, UpstreamPoll *upstreamPoll) {
    DownstreamNode *node = create_upstream_node(broker, upstreamPoll->name);

    node->upstreamPoll = upstreamPoll;

    RemoteDSLink *link = upstreamPoll->remoteDSLink;

    node->dsId = dslink_str_ref(dslink_strdup(upstreamPoll->dsId));
    link->dsId = node->dsId;
    link->node = node;

    uv_timer_t *ping_timer = NULL;
    ping_timer = dslink_malloc(sizeof(uv_timer_t));
    ping_timer->data = link;
    uv_timer_init(mainLoop, ping_timer);
    uv_timer_start(ping_timer, dslink_handle_ping, 1000, 30000);
    link->pingTimerHandle = ping_timer;

    // set the ->link and update all existing stream
    broker_dslink_connect(node, link);
}
