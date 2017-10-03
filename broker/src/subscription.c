#include <broker/subscription.h>
#include <dslink/utils.h>
#include <broker/net/ws.h>
#include <broker/config.h>
#include <broker/broker.h>

#define LOG_TAG "subscription"

#include <dslink/log.h>

#include <string.h>

static int removeFromMessageQueue(SubRequester *subReq, uint32_t msgId);
static int sendMessage(SubRequester *subReq, json_t *varray, uint32_t* msgId);

static const uint32_t SEND_MAX_QUEUE = 8;


int cmp_pack(const void* lhs, const void* rhs)
{
    PendingAck* lpack = (PendingAck*)lhs;
    PendingAck* rpack = (PendingAck*)rhs;
    if(lpack->msg_id == rpack->msg_id) {
        return 0;
    } else if(lpack->msg_id > rpack->msg_id) {
        return 1;
    }
    return -1;
}

int cmp_int(const void* lhs, const void* rhs)
{
    if(*(int*)lhs == *(int*)rhs) {
        return 0;
    } else if(*(int*)lhs > *(int*)rhs) {
        return 1;
    }
    return -1;
}

int check_subscription_ack(RemoteDSLink *link, uint32_t ack)
{
    PendingAck search_pack = { NULL, ack };
    log_info("Receiving ack from %s: %d\n", link->name, ack);

    uint32_t last = vector_upper_bound(link->node->pendingAcks, &search_pack, cmp_pack);

    for (long idx = (long)last-1; idx >= 0; --idx) { 
      PendingAck pack = *(PendingAck*)vector_get(link->node->pendingAcks, idx);
      SubRequester *subReq = pack.subscription;
      
      if ( removeFromMessageQueue(subReq, pack.msg_id) ) { 
	sendQueuedMessages(subReq);
      }      
    }
    vector_remove_range(link->node->pendingAcks, 0, last);
    return 0;
}


void send_subscribe_request(DownstreamNode *node,
                            const char *path,
                            uint32_t sid,
                            uint8_t qos) {
    json_t *top = json_object();
    json_t *reqs = json_array();
    json_object_set_new_nocheck(top, "requests", reqs);

    json_t *req = json_object();
    json_array_append_new(reqs, req);

    uint32_t rid = broker_node_incr_rid(node);
    json_object_set_new_nocheck(req, "rid", json_integer(rid));
    json_object_set_new_nocheck(req, "method", json_string_nocheck("subscribe"));
    json_t *paths = json_array();
    json_object_set_new_nocheck(req, "paths", paths);
    json_t *p = json_object();
    json_array_append_new(paths, p);
    json_object_set_new_nocheck(p, "path", json_string_nocheck(path));
    json_object_set_new_nocheck(p, "sid", json_integer(sid));
    json_object_set_new_nocheck(p, "qos", json_integer(qos));

    broker_ws_send_obj(node->link, top);
    json_decref(top);
}


SubRequester *broker_create_sub_requester(DownstreamNode * node, const char *path, uint32_t reqSid, uint8_t qos, json_t *qosQueue) {
    SubRequester *req = dslink_calloc(1, sizeof(SubRequester));
    memset(req, 0, sizeof(SubRequester));
    if (qosQueue) {
        req->qosQueue = qosQueue;
        json_incref(qosQueue);
    } else if (qos > 2) {
        req->qosQueue = json_array();
    }
    req->path = dslink_strdup(path);
    req->reqNode = node;
    req->reqSid = reqSid;
    req->qos = qos;
    return req;
}

void serialize_qos_queue(SubRequester *subReq, uint8_t delete) {
    if (!subReq->qosKey1) {
        subReq->qosKey1 = dslink_str_escape(subReq->reqNode->path);
    }
    if (!subReq->qosKey2) {
        subReq->qosKey2 = dslink_str_escape(subReq->path);
    }
    if (delete) {
        dslink_storage_store(((Broker *)mainLoop->data)->storage, subReq->qosKey1, subReq->qosKey2, NULL, NULL, NULL);
    } else {
        json_t *array = json_array();
        json_array_append_new(array, json_integer(subReq->qos));
        json_array_append(array, subReq->qosQueue);
        dslink_storage_store(((Broker *)mainLoop->data)->storage, subReq->qosKey1, subReq->qosKey2, array, NULL, NULL);
        json_decref(array);
    }

}

void broker_free_sub_requester(SubRequester *req) {
    dslink_map_remove(&req->reqNode->req_sub_paths, (void*)req->path);

    if (req->reqSid != 0xFFFFFFFF) {
        // while still waiting for qos requester to connect
        dslink_map_remove(&req->reqNode->req_sub_sids, &req->reqSid);
    }

    if (req->pendingNode) {
        // pending;
        list_remove_node(req->pendingNode);
        dslink_free(req->pendingNode);
        req->pendingNode = NULL;
    }
    if (req->stream) {
        dslink_map_remove(&req->stream->reqSubs, req->reqNode);
        if (req->stream->reqSubs.size == 0) {
            broker_stream_free((BrokerStream *)req->stream);
        }
    }
    if (req->qos > 2) {
        serialize_qos_queue(req, 1);
        dslink_storage_store(((Broker *)mainLoop->data)->storage, req->reqNode->path, req->path, NULL, NULL, NULL);
    }
    if (req->qosQueue) {
        clear_qos_queue(req, 1);
        json_decref(req->qosQueue);
    }
    if(req->messageQueue) {
        rb_free(req->messageQueue);
        dslink_free(req->messageQueue);
        req->messageQueue = NULL;
    }

    dslink_free(req->path);
    dslink_free(req->qosKey1);
    dslink_free(req->qosKey2);
    dslink_free(req);
}

void broker_clear_messsage_ids(SubRequester *subReq)
{
  while (subReq->messageOutputQueueCount) {
    --subReq->messageOutputQueueCount;
    QueuedMessage* m = rb_at(subReq->messageQueue, subReq->messageOutputQueueCount);
    if(!m) {
      break;
    }
    m->msg_id = 0;
  }
}


void clear_qos_queue(SubRequester *subReq, uint8_t serialize) {
    json_array_clear(subReq->qosQueue);
    if (serialize && subReq->qos > 2) {
        serialize_qos_queue(subReq, 0);
    }
}

void broker_update_sub_req_qos(SubRequester *subReq) {
    if (subReq->reqNode->link) {

        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_t *newResp = json_object();
        json_array_append_new(resps, newResp);
        json_object_set_new_nocheck(newResp, "rid", json_integer(0));

        size_t idx;
        json_t *varray;
        json_array_foreach(subReq->qosQueue, idx, varray) {
            json_array_set_new(varray, 0, json_integer(subReq->reqSid));
        }
        json_object_set_nocheck(newResp, "updates", subReq->qosQueue);

        broker_ws_send_obj(subReq->reqNode->link, top);

        json_decref(top);
        clear_qos_queue(subReq, 1);
    }
}

static int addPendingAck(SubRequester *subReq, uint32_t msgId)
{
    DownstreamNode* node = (DownstreamNode*)(subReq->reqNode->link->node);
    if(!node->pendingAcks) {
        node->pendingAcks = (Vector*)dslink_malloc(sizeof(Vector));
        vector_init(node->pendingAcks, 64, sizeof(PendingAck));
    }
    PendingAck pack = { subReq, msgId };
    vector_append(node->pendingAcks, &pack);

    return 0;
}

void cleanup_queued_message(void* message) {
    QueuedMessage* m = message;
    if(m) {
        json_decref(m->message);
    }
}

int sendQueuedMessages(SubRequester *subReq) {
    int result = 1;

    if(rb_count(subReq->messageQueue)) {
        while (subReq->messageOutputQueueCount < SEND_MAX_QUEUE) {
            QueuedMessage* m = rb_at(subReq->messageQueue, subReq->messageOutputQueueCount);
            if(!m) {
                break;
            }
            if(m->msg_id > 0) {
                log_err("Has been send already: %d\n", m->msg_id);
                break;
            }
            result &= sendMessage(subReq, m->message, &m->msg_id);
        }
    }
    return result;
}

static int sendMessage(SubRequester *subReq, json_t *varray, uint32_t* msgId) 
{
    json_t *top = json_object();
    json_t *resps = json_array();
    json_object_set_new_nocheck(top, "responses", resps);
    json_t *newResp = json_object();
    json_array_append_new(resps, newResp);
    json_object_set_new_nocheck(newResp, "rid", json_integer(0));
    json_t *updates = json_array();
    json_object_set_new_nocheck(newResp, "updates", updates);

    json_array_set_new(varray, 0, json_integer(subReq->reqSid));
    json_array_append(updates, varray);

    *msgId = broker_ws_send_obj(subReq->reqNode->link, top);
    json_decref(top);

    ++subReq->messageOutputQueueCount;

     log_info("Send message with msgId %d\n", *msgId);

    return addPendingAck(subReq, *msgId);
}

static void addToMessageQueue(SubRequester *subReq, json_t *varray, uint32_t msgId) {

     log_info("Add message with msgId %d to MessageQueue\n", msgId);


    if(!subReq->messageQueue) {
        subReq->messageQueue = (Ringbuffer*)dslink_malloc(sizeof(Ringbuffer));
        // TODO lfuerste: maybe use a lesser value for QOS == 0?
        rb_init(subReq->messageQueue, broker_max_qos_queue_size, sizeof(QueuedMessage), cleanup_queued_message);
    }
    QueuedMessage m = { json_incref(varray),  msgId};
    if(rb_push(subReq->messageQueue, &m) > 0) {
        log_debug("Skipping a value because the queue is full: sid %d\n", subReq->reqSid);
    }
}

static int removeFromMessageQueue(SubRequester *subReq, uint32_t msgId) {
   int result = 0;

    log_info("Remove message with msgId %d from MessageQueue\n", msgId);

    if(subReq->messageQueue) {
        while(rb_count(subReq->messageQueue)) {
            QueuedMessage* m = rb_front(subReq->messageQueue);

            if(m->msg_id == 0 || m->msg_id > msgId) {
                break;
            }
	    ++result;
            rb_pop(subReq->messageQueue);
	    log_info("Removing message with msgId %d from MessageQueue\n", m->msg_id);

            --subReq->messageOutputQueueCount;
        }
    }
    return result;
}

int broker_update_sub_req(SubRequester *subReq, json_t *varray) {
    int result = 1;

    uint32_t msgId = 0;

    if ( subReq->qos <= 2 ) {
        // We need to send the message first to get a message id
        if (subReq->reqNode->link && subReq->messageOutputQueueCount < SEND_MAX_QUEUE) {
            result = sendMessage(subReq, varray, &msgId);
            log_info("Sending with msgid: %d\n", msgId);
        } else {
            log_info("Send queue full: %d\n", subReq->reqSid);
        }
        // Now add the message with or without its message id to the queue
        addToMessageQueue(subReq, varray, msgId);
    } else {
        if (subReq->reqNode->link ) {
            result = sendMessage(subReq, varray, &msgId);
            --subReq->messageOutputQueueCount;
        } else {
            // add to qos queue
            if (!subReq->qosQueue) {
                subReq->qosQueue = json_array();
            }
            if (json_array_size(subReq->qosQueue) >= broker_max_qos_queue_size) {
                // destroy qos queue when exceed max queue size
                clear_qos_queue(subReq, 1);
                return result;
            }
            json_array_append(subReq->qosQueue, varray);
            serialize_qos_queue(subReq, 0);
        }
    }
    
    
    return result;
}

static
int broker_update_sub_reqs(BrokerSubStream *stream, json_t *responder_msg_id) {
  int result = 1;

  dslink_map_foreach(&stream->reqSubs) {
    SubRequester *req = entry->value->data;
    result &= broker_update_sub_req(req, stream->last_value);
    if ( !result && responder_msg_id ) {
      json_decref(stream->last_pending_responder_msg_id);
      stream->last_pending_responder_msg_id = json_incref(responder_msg_id);
    }
  }
  return result;
}
int broker_update_sub_stream(BrokerSubStream *stream, json_t *varray, json_t *responder_msg_id) {
    json_decref(stream->last_value);
    stream->last_value = varray;
    json_incref(varray);
    return broker_update_sub_reqs(stream, responder_msg_id);
}

int broker_update_sub_stream_value(BrokerSubStream *stream, json_t *value, json_t *ts, json_t *responder_msg_id) {
    json_decref(stream->last_value);
    json_t *varray = json_array();
    json_array_append(varray, json_null());
    json_array_append(varray, value);

    if (!ts) {
        // create ts and
        char tsbuff[30];
        dslink_create_ts(tsbuff, 30);
        ts = json_string_nocheck(tsbuff);
        json_array_append_new(varray, ts);
    } else {
        json_array_append(varray, ts);
    }

    stream->last_value = varray;
    return broker_update_sub_reqs(stream, responder_msg_id);
}

void broker_update_stream_qos(BrokerSubStream *stream) {
    if (stream && stream->remote_path) {
        uint8_t maxQos = 0;
        // recalculate remoteQos;
        dslink_map_foreach(&stream->reqSubs) {
            SubRequester *reqSub = entry->value->data;
          if(maxQos < reqSub->qos) {
              maxQos = reqSub->qos;
          }
        }
        if (maxQos != stream->respQos && ((DownstreamNode*)stream->respNode)->link) {
            stream->respQos = maxQos;
            send_subscribe_request((DownstreamNode*)stream->respNode, stream->remote_path, stream->respSid, stream->respQos);
        } else {
            stream->respQos = maxQos;
        }
    }
}

void broker_update_sub_qos(SubRequester *req, uint8_t qos) {
    if (req->qos != qos) {
        uint8_t oldqos = req->qos;
        req->qos = qos;
        if (oldqos ==3 && qos != 3) {
            // delete qos file
            serialize_qos_queue(req, 1);
        }

        if (req->qos > 0 && !(req->qosQueue)) {
            req->qosQueue = json_array();
        }
        broker_update_stream_qos(req->stream);
        if (qos == 3 && oldqos != 3) {
            // save qos file
            serialize_qos_queue(req, 0);
        }
    }
}
