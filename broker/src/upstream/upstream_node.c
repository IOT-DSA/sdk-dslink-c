#include <broker/upstream/upstream_node.h>
#include <broker/msg/msg_invoke.h>
#include <broker/broker.h>
#include <broker/upstream/upstream_handshake.h>
#include <broker/handshake.h>
#include <broker/msg/msg_list.h>
#include <dslink/utils.h>

int broker_upstream_node_populate(BrokerNode *upstreamNode) {
    (void)upstreamNode;
    return 0;
}





void init_upstream_node(Broker *broker, UpstreamPoll *upstreamPoll) {

    DownstreamNode *node = NULL;
    ref_t *ref = dslink_map_get(broker->upstream->children,
                                (char *) upstreamPoll->name);
    if (!ref) {
        node = broker_init_downstream_node(broker->upstream, upstreamPoll->name);

        if (broker->upstream->list_stream) {
            update_list_child(broker->upstream,
                              broker->upstream->list_stream,
                              upstreamPoll->name);
        }
    } else {
        node = ref->data;
    }

    RemoteDSLink *link = upstreamPoll->remoteDSLink;
//    if (node->link) {
//        broker_close_link(node->link);
//    }

    node->dsId = dslink_str_ref(dslink_strdup(upstreamPoll->dsId));
    link->dsId = node->dsId;
    link->node = node;

    uv_timer_t *ping_timer = NULL;
    ping_timer = dslink_malloc(sizeof(uv_timer_t));
    ping_timer->data = link;
    uv_timer_init(upstreamPoll->loop, ping_timer);
    uv_timer_start(ping_timer, dslink_handle_ping, 1000, 30000);
    link->pingTimerHandle = ping_timer;

    // set the ->link and update all existing stream
    broker_dslink_connect(node, link);
}

