#include <string.h>

#include <dslink/utils.h>
#include <dslink/col/list.h>
#include <broker/subscription.h>

#include "broker/utils.h"
#include "broker/stream.h"
#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/msg/msg_subscribe.h"

void broker_handle_local_subscribe(BrokerNode *respNode,
                                   SubRequester *subreq) {
    DownstreamNode *reqNode = subreq->reqNode;

    if (!respNode->sub_stream) {
        respNode->sub_stream = broker_stream_sub_init();
        respNode->sub_stream->respNode = respNode;
        if (respNode->value) {
            broker_update_sub_stream_value(respNode->sub_stream, respNode->value, NULL);
        } else {
            broker_update_sub_stream_value(respNode->sub_stream, json_null(), NULL);
        }
    }
    subreq->stream = respNode->sub_stream;
    dslink_map_set(&respNode->sub_stream->reqSubs, dslink_ref(reqNode, NULL), dslink_ref(subreq, NULL));
    if (respNode->sub_stream->last_value) {
        broker_update_sub_req(subreq, respNode->sub_stream->last_value);
    }
}

void broker_subscribe_remote(DownstreamNode *respNode, SubRequester *subreq,
                             const char *respPath) {
    DownstreamNode *reqNode = subreq->reqNode;

    ref_t *ref = dslink_map_get(&respNode->resp_sub_streams, (void*)respPath);
    BrokerSubStream *bss;
    if (ref) {
        bss = ref->data;
    } else {
        bss = broker_stream_sub_init();
        bss->respSid =  broker_node_incr_sid(respNode);
        bss->remote_path = dslink_strdup(respPath);
        bss->respNode = (BrokerNode*)respNode;
        // a invalid qos value, so the newQos != qos,
        // which will send a new subscribe method to responder
        bss->respQos = 0xFF;
        dslink_map_set(&respNode->resp_sub_streams, dslink_str_ref(bss->remote_path), dslink_ref(bss, NULL));
        dslink_map_set(&respNode->resp_sub_sids, dslink_int_ref(bss->respSid), dslink_ref(bss, NULL));
    }

    subreq->stream = bss;
    dslink_map_set(&bss->reqSubs, dslink_ref(reqNode, NULL), dslink_ref(subreq, NULL));

    broker_update_stream_qos(bss);
    if (bss->last_value) {
        broker_update_sub_req(subreq, bss->last_value);
    }
}


static
void subs_list_free(void *p) {
    List *subs = p;
    dslink_list_foreach_nonext(subs) {
        ListNode *entry = (ListNode *) node;
        entry->list = NULL; //avoid list_remove_node
        SubRequester *sub = entry->value;
        sub->pendingNode = NULL;
        ListNodeBase *tmp = node->next;
        if ((intptr_t) node != (intptr_t) subs) {
            dslink_free(node);
        }
        node = tmp;
    }

    dslink_free(subs);
}

void broker_subscribe_disconnected_remote(const char *path,
                                          SubRequester *subreq) {
    Broker *broker = mainLoop->data;

    const size_t len = broker_downstream_node_base_len(path);
    if (len ==0) {
        // todo remove subreq?
        return;
    }
    ref_t *ref = dslink_map_getl(&broker->remote_pending_sub,
                                 (char *) path, len);
    List *subs;
    if (ref) {
        subs = ref->data;
    } else {
        subs = dslink_calloc(1, sizeof(List));
        list_init(subs);
        dslink_map_set(&broker->remote_pending_sub,
                       dslink_strl_ref(path, len),
                       dslink_ref(subs, subs_list_free));
    }

    subreq->pendingNode = dslink_list_insert(subs, subreq);
}

void broker_subscribe_local_nonexistent(const char *path, SubRequester *subreq) {
    Broker *broker = mainLoop->data;
    ref_t *ref = dslink_map_get(&broker->local_pending_sub, (char *) path);
    List *subs;
    if (ref) {
        subs = ref->data;
    } else {
        subs = dslink_calloc(1, sizeof(List));
        list_init(subs);
        dslink_map_set(&broker->local_pending_sub,
                       dslink_str_ref(path),
                       dslink_ref(subs, subs_list_free));
    }

    subreq->pendingNode = dslink_list_insert(subs, subreq);
}


void broker_add_new_subscription(Broker *broker, SubRequester *subreq) {
    char *out = NULL;
    DownstreamNode * reqNode = subreq->reqNode;
    BrokerNode *respNode = broker_node_get(broker->root, subreq->path, &out);

    dslink_map_set(&reqNode->req_sub_paths, dslink_str_ref(subreq->path), dslink_ref(subreq, NULL));
    dslink_map_set(&reqNode->req_sub_sids, dslink_int_ref(subreq->reqSid), dslink_ref(subreq, NULL));

    if (!respNode) {
        if (dslink_str_starts_with(subreq->path, "/downstream/") || dslink_str_starts_with(subreq->path, "/upstream/")) {
            broker_subscribe_disconnected_remote(subreq->path, subreq);
        } else {
            broker_subscribe_local_nonexistent(subreq->path, subreq);
        }
        return;
    }

    if (respNode->type == REGULAR_NODE) {
        broker_handle_local_subscribe( respNode, subreq);
    } else {
        DownstreamNode *downNode = (DownstreamNode *)respNode;
        broker_subscribe_remote(downNode, subreq, out);
    }
}

static
void handle_subscribe(RemoteDSLink *link, json_t *sub) {
    const char *path = json_string_value(json_object_get(sub, "path"));
    json_t *jSid = json_object_get(sub, "sid");
    if (!(path && jSid)) {
        return;
    }

    PermissionLevel permissionOnPath = get_permission(path, link->broker->root, link);
    if (permissionOnPath < PERMISSION_READ) {
        return;
    }

    DownstreamNode *reqNode = link->node;



    uint32_t sid = (uint32_t) json_integer_value(jSid);

    json_t *jQos = json_object_get(sub, "qos");
    uint8_t qos = 0;

    if (json_is_integer(jQos)) {
        qos = (uint8_t) json_integer_value(jQos);
    }

    // TODO check if sid or path already exist

    ref_t *idsub = dslink_map_get(&reqNode->req_sub_sids, &sid);
    ref_t *pathsub = dslink_map_get(&reqNode->req_sub_paths, (void*)path);

    if (idsub && pathsub && idsub->data == pathsub->data) {
        // update qos only
        SubRequester *reqsub = idsub->data;
        broker_update_sub_qos(reqsub, qos);
        return;
    }

    if (idsub) {
        // remove current sub;
        SubRequester *reqsub = idsub->data;
        broker_free_sub_requester(reqsub);
    }
    if (pathsub) {
        // update sid and qos on existing path;
        SubRequester *reqsub = pathsub->data;
        ref_t *pathidsub = dslink_map_remove_get(&reqNode->req_sub_sids, &reqsub->reqSid);
        if (pathidsub) {
            dslink_free(pathidsub);
        }
        reqsub->reqSid = sid;
        dslink_map_set(&reqNode->req_sub_sids, dslink_int_ref(sid), dslink_ref(reqsub, NULL));
        broker_update_sub_qos(reqsub, qos);
        if (json_array_size(reqsub->qosQueue) > 0) {
            // send qos data
            broker_update_sub_req_qos(reqsub);
        } else if (reqsub->stream && reqsub->stream->last_value) {
            broker_update_sub_req(reqsub, reqsub->stream->last_value);
        }
        return;
    }

    SubRequester *subreq = broker_create_sub_requester(reqNode, path, sid, qos, NULL);
    if (qos & 2) {
        serialize_qos_queue(subreq, 0);
    }
    broker_add_new_subscription(link->broker, subreq);
}

int broker_msg_handle_subscribe(RemoteDSLink *link, json_t *req) {
    broker_utils_send_closed_resp(link, req, NULL);

    json_t *paths = json_object_get(req, "paths");
    if (!json_is_array(paths)) {
        return 1;
    }


    json_t *maxPermitJson = json_object_get(req, "permit");
    PermissionLevel maxPermit = PERMISSION_CONFIG;
    if (json_is_string(maxPermitJson)) {
        maxPermit = permission_str_level(json_string_value(maxPermitJson));
    }

    if (maxPermit < PERMISSION_READ) {
        return 0;
    }

    size_t index;
    json_t *obj;
    json_array_foreach(paths, index, obj) {
        handle_subscribe(link, obj);
    }

    return 0;
}
