#include <broker/upstream/upstream_node.h>
#include <broker/broker.h>
#include <broker/upstream/upstream_handshake.h>
#include <broker/handshake.h>
#include <broker/msg/msg_list.h>
#include <broker/net/ws.h>

#define LOG_TAG "upstream"
#include <dslink/log.h>
#include <dslink/utils.h>

#include <string.h>

#include <sys/time.h>

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

void dslink_handle_upstream_ping(uv_timer_t* handle)
{  
  UpstreamPoll *upstreamPoll = handle->data;
  if ( !upstreamPoll ) {
    return;
  }
  
  RemoteDSLink *link = upstreamPoll->remoteDSLink;
  if ( !link ) {
    return;
  }  

  if (link->lastWriteTime) {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    long time_diff = current_time.tv_sec - link->lastWriteTime->tv_sec;
    if (time_diff >= 60) {
      log_debug("Send heartbeat to upstream %s\n", link->name );
      broker_ws_send_obj(link, json_object());
    }
  } else {
    log_debug("Send heartbeat to upstream %s\n", link->name );
    broker_ws_send_obj(link, json_object());
  }

  if (link->lastReceiveTime) {
    struct timeval current_time;
    gettimeofday(&current_time, NULL);
    long time_diff = current_time.tv_sec - link->lastReceiveTime->tv_sec;
    if (time_diff >= 90) {
      log_info("Disconnecting upstream %s due to missing heartbeat response\n", link->name );
      
      if ( link->client && link->client->poll_cb ) {
#ifdef ETIMEDOUT
	(*link->client->poll_cb)(upstreamPoll->wsPoll, -(ETIMEDOUT), UV_DISCONNECT );
#else
	(*link->client->poll_cb)(upstreamPoll->wsPoll, -32, UV_DISCONNECT );
#endif
      }
    }
  }
}

void init_upstream_node(Broker *broker, UpstreamPoll *upstreamPoll) {
    DownstreamNode *node = create_upstream_node(broker, upstreamPoll->name);

    node->upstreamPoll = upstreamPoll;

    RemoteDSLink *link = upstreamPoll->remoteDSLink;

    node->dsId = dslink_str_ref(dslink_strdup(upstreamPoll->dsId));
    link->dsId = node->dsId;
    link->node = node;

    uv_timer_t *ping_timer = dslink_malloc(sizeof(uv_timer_t));
    ping_timer->data = upstreamPoll;
    uv_timer_init(mainLoop, ping_timer);
    uv_timer_start(ping_timer, dslink_handle_upstream_ping, 1000, 30000);
    link->pingTimerHandle = ping_timer;

    // set the ->link and update all existing stream
    broker_dslink_connect(node, link);
}
