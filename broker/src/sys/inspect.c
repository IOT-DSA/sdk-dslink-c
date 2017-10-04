
#include <broker/sys/inspect.h>
#include <broker/broker.h>
#include <broker/utils.h>
#include <broker/subscription.h>
#include <broker/msg/msg_invoke.h>
#include <broker/net/ws.h>

static void add_subscriptions(DownstreamNode *node, json_t* array)
{
  dslink_map_foreach( &node->req_sub_paths ) {
    SubRequester* subRequester = entry->value->data;
    
    json_t* subscriptionRow = json_array();
    json_array_append_new(subscriptionRow,  json_string(subRequester->path));
    json_array_append_new(subscriptionRow,  json_string(subRequester->reqNode->path));
    json_array_append_new(subscriptionRow,  json_integer(subRequester->qos));

    if ( subRequester->messageQueue ) {
      uint32_t queueSize = rb_count( subRequester->messageQueue );
      
      uint32_t pendingAcks;
      for ( pendingAcks = 0; pendingAcks < subRequester->messageQueue->count; ++pendingAcks ) {
	QueuedMessage* m = rb_at(subRequester->messageQueue, pendingAcks);
	if ( !m || !m->msg_id ) {
	  break;
	}
      }
      json_array_append_new(subscriptionRow,  json_integer(queueSize));
      json_array_append_new(subscriptionRow,  json_integer(pendingAcks));
    } else if (subRequester->qosQueue) {
      json_array_append_new(subscriptionRow,  json_integer(json_array_size(subRequester->qosQueue)));
      json_array_append_new(subscriptionRow,  json_null());

    } else {
      json_array_append_new(subscriptionRow,  json_integer(0));
      json_array_append_new(subscriptionRow,  json_integer(0));
    }

    json_array_append_new( array, subscriptionRow );
  }
}


static
void inspect_subscriptions(RemoteDSLink *link,
			   BrokerNode *node,
			   json_t *req,
			   PermissionLevel maxPermission)
{
    (void)node;
    if (maxPermission < PERMISSION_CONFIG) {
        broker_utils_send_closed_resp(link, req, "permissionDenied");
        return;
    }

    Broker* broker = link->broker;

    /*
    json_t *params = json_object_get(req, "params");
    if (!json_is_object(params)) {
        broker_utils_send_closed_resp(link, req, "invalidParameter");
        return;
    }

    json_t *level = json_object_get(params, "Level");
    if (!json_is_string(level)) {
        broker_utils_send_closed_resp(link, req, "invalidParameter");
        return;
    }
    const char* name = json_string_value(level);
    dslink_log_set_lvl(name);
    */


  json_t* rid = json_object_get(req, "rid");
  if(!rid) {
    return;
  }

  json_t* top = json_object();
  if (!top) {
    return;
  }
  json_t* resps = json_array();
  if (!resps) {
    json_delete(top);
    return;
  }
  json_object_set_new_nocheck(top, "responses", resps);

  json_t* resp = json_object();
  if (!resp) {
    json_delete(top);
    return;
  }
  json_array_append_new(resps, resp);
  json_object_set_nocheck(resp, "rid", rid);

  json_t* updates = json_array();
  json_object_set_new_nocheck(resp, "updates", updates);

  dslink_map_foreach(broker->downstream->children) {
    add_subscriptions( entry->value->data, updates );
  }

  dslink_map_foreach(broker->upstream->children) {
    add_subscriptions( entry->value->data, updates );
  }
  
  json_object_set_new_nocheck(resp, "stream", json_string("closed"));

  broker_ws_send_obj(link, top);
  json_delete(top);
}

static int init_inspect_subscriptions(BrokerNode *sysNode)
{
    BrokerNode *inspectSubscriptionsNode = broker_node_create("inspectSubscriptions", "node");
    if (!inspectSubscriptionsNode) {
        return 1;
    }


    if(json_object_set_new_nocheck(inspectSubscriptionsNode->meta, "$actionGroup", json_string_nocheck("Inspect")) != 0) {
        return 1;
    }

    if (json_object_set_new_nocheck(inspectSubscriptionsNode->meta, "$invokable",
                                    json_string_nocheck("write")) != 0) {
        return 1;
    }

    if (json_object_set_new_nocheck(inspectSubscriptionsNode->meta, "$name",
                                    json_string_nocheck("Subscriptions")) != 0) {
        return 1;
    }

    /*
    json_error_t err;
    json_t *params = json_loads("[{\"name\":\"Level\",\"type\":\"enum[off,fatal,error,warn,info,debug]\"}]", 0, &err);
    if (json_object_set_new_nocheck(inspectSubscriptionsNode->meta, "$params", params) != 0) {
        return 1;
    }
    */

    json_t *columnList = json_array();
    if (broker_invoke_create_param(columnList, "path", "string") != 0
        || broker_invoke_create_param(columnList, "requester", "string") != 0
        || broker_invoke_create_param(columnList, "qos", "number") != 0
        || broker_invoke_create_param(columnList, "queued_messages", "number") != 0
        || broker_invoke_create_param(columnList, "pending_acks", "number") != 0
        || json_object_set_new_nocheck(inspectSubscriptionsNode->meta, "$columns", columnList) != 0) {
        goto fail;
    }

    if ( json_object_set_new_nocheck(inspectSubscriptionsNode->meta, "$result", json_string("table")) ) {
      goto fail;
    }

    inspectSubscriptionsNode->on_invoke = inspect_subscriptions;

    if (broker_node_add( sysNode, inspectSubscriptionsNode) != 0) {
        goto fail;
    }


    return 0;

fail:
    json_decref(columnList);
    // json_decref(paramList);
    broker_node_free(inspectSubscriptionsNode);

    return 1;
}


int init_inspect(BrokerNode *sysNode)
{
  return init_inspect_subscriptions(sysNode);
}

