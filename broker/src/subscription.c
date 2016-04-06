#include <broker/subscription.h>
#include <dslink/utils.h>
#include <broker/net/ws.h>


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
    json_object_set_new_nocheck(req, "method", json_string("subscribe"));
    json_t *paths = json_array();
    json_object_set_new_nocheck(req, "paths", paths);
    json_t *p = json_object();
    json_array_append_new(paths, p);
    json_object_set_new_nocheck(p, "path", json_string(path));
    json_object_set_new_nocheck(p, "sid", json_integer(sid));
    json_object_set_new_nocheck(p, "qos", json_integer(qos));

    broker_ws_send_obj(node->link, top);
    json_decref(top);
}


SubRequester *broker_create_sub_requester(DownstreamNode * node, const char *path, uint32_t reqSid, uint8_t qos, List *qosQueue) {
    SubRequester *req = dslink_calloc(1, sizeof(SubRequester));
    if (qosQueue) {
        req->qosQueue = qosQueue;
    } else if (qos > 0) {
        req->qosQueue = dslink_malloc(sizeof(List));
        list_init(req->qosQueue);
    }
    req->path = dslink_strdup(path);
    req->reqNode = node;
    req->reqSid = reqSid;
    req->qos = qos;
    return req;
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
    if (req->qosQueue) {
        clear_qos_queue(req->qosQueue);
        dslink_free(req->qosQueue);
    }
    dslink_free(req);
}

void clear_qos_queue(List *qosQueue) {
    dslink_list_foreach(qosQueue) {
        ListNode *lnode = (ListNode *)node;
        json_decref(lnode->value);
    }
    dslink_list_free_all_nodes(qosQueue);
}


void broker_update_sub_req_qos(SubRequester *subReq) {
    if (subReq->reqNode->link) {

        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_t *newResp = json_object();
        json_array_append_new(resps, newResp);
        json_object_set_new_nocheck(newResp, "rid", json_integer(0));
        json_t *updates = json_array();
        json_object_set_new_nocheck(newResp, "updates", updates);
        dslink_list_foreach(subReq->qosQueue) {
            json_t *varray = ((ListNode*)node)->value;
            json_array_set_new(varray, 0, json_integer(subReq->reqSid));
            json_array_append(updates, varray);
        }

        broker_ws_send_obj(subReq->reqNode->link, top);

        json_decref(top);
        clear_qos_queue(subReq->qosQueue);
    }
}

void broker_update_sub_req(SubRequester *subReq, json_t *varray) {
    if (subReq->reqNode->link) {

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

        broker_ws_send_obj(subReq->reqNode->link, top);

        json_decref(top);
    } else if (subReq->qos > 0){
        // add to qos queue
        if (!subReq->qosQueue) {
            subReq->qosQueue = dslink_malloc(sizeof(List));
            list_init(subReq->qosQueue);
        }
        if ((subReq->qos & 1) == 0) {
            clear_qos_queue(subReq->qosQueue);
        }
        dslink_list_insert(subReq->qosQueue, varray);
        json_incref(varray);
    }
}

static
void broker_update_sub_reqs(BrokerSubStream *stream) {
    dslink_map_foreach(&stream->reqSubs) {
        SubRequester *req = entry->value->data;
        broker_update_sub_req(req, stream->last_value);
    }
}
void broker_update_sub_stream(BrokerSubStream *stream, json_t *varray) {
    json_decref(stream->last_value);
    stream->last_value = varray;
    json_incref(varray);
    broker_update_sub_reqs(stream);
}

void broker_update_sub_stream_value(BrokerSubStream *stream, json_t *value, json_t *ts) {
    json_decref(stream->last_value);
    json_t *varray = json_array();
    json_array_append(varray, json_null());
    json_array_append(varray, value);

    if (!ts) {
        // create ts and
        char tsbuff[30];
        dslink_create_ts(tsbuff, 30);
        ts = json_string(tsbuff);
        json_array_append_new(varray, ts);
    } else {
        json_array_append(varray, ts);
    }

    stream->last_value = varray;
    broker_update_sub_reqs(stream);
}

void broker_update_stream_qos(BrokerSubStream *stream) {
    if (stream && stream->remote_path) {
        uint8_t maxQos = 0;
        // recalculate remoteQos;
        dslink_map_foreach(&stream->reqSubs) {
            SubRequester *reqSub = entry->value->data;
            maxQos |= reqSub->qos;
        }
        if (maxQos != stream->respQos && ((DownstreamNode*)stream->respNode)->link) {
            stream->respQos = maxQos;
            send_subscribe_request((DownstreamNode*)stream->respNode, stream->remote_path, stream->respSid, stream->respQos);
        }
    }
}
void broker_update_sub_qos(SubRequester *req, uint8_t qos) {
    if (req->qos != qos) {
        req->qos = qos;
        if (req->qos > 0 && !(req->qosQueue)) {
            req->qosQueue = dslink_malloc(sizeof(List));
            list_init(req->qosQueue);
        }
        broker_update_stream_qos(req->stream);
    }
}
