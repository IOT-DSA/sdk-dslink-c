#include <broker/subscription.h>
#include <dslink/utils.h>
#include <broker/net/ws.h>
#include <broker/config.h>
#include <broker/broker.h>


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
    if (qosQueue) {
        req->qosQueue = qosQueue;
        json_incref(qosQueue);
    } else if (qos > 0) {
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
    if (req->qos & 2) {
        serialize_qos_queue(req, 1);
        dslink_storage_store(((Broker *)mainLoop->data)->storage, req->reqNode->path, req->path, NULL, NULL, NULL);
    }
    if (req->qosQueue) {
        clear_qos_queue(req, 1);
        json_decref(req->qosQueue);
    }
    dslink_free(req->path);
    dslink_free(req->qosKey1);
    dslink_free(req->qosKey2);
    dslink_free(req);

}

void clear_qos_queue(SubRequester *subReq, uint8_t serialize) {
    json_array_clear(subReq->qosQueue);
    if (serialize && subReq->qos & 2) {
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
            subReq->qosQueue = json_array();
        }
        if ((subReq->qos & 1) == 0) {
            clear_qos_queue(subReq, 0);
        } else if (json_array_size(subReq->qosQueue) >= broker_max_qos_queue_size) {
            // destroy qos queue when exceed max queue size
            clear_qos_queue(subReq, 1);
            subReq->qos = 0;
            return;
        }
        json_array_append(subReq->qosQueue, varray);
        if (subReq->qos & 2) {
            serialize_qos_queue(subReq, 0);
        }
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
        ts = json_string_nocheck(tsbuff);
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
        uint8_t oldqos = req->qos;
        req->qos = qos;
        if (oldqos & 2 && !(qos & 2)) {
            // delete qos file
            serialize_qos_queue(req, 1);
        }

        if (req->qos > 0 && !(req->qosQueue)) {
            req->qosQueue = json_array();
        }
        broker_update_stream_qos(req->stream);
        if (qos & 2 && !(oldqos & 2)) {
            // save qos file
            serialize_qos_queue(req, 0);
        }
    }
}
