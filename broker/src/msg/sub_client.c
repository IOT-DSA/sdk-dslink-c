#include <broker/msg/msg_subscribe.h>

SubRequester *broker_create_sub_requester(RemoteDSLink * requester, uint32_t reqSid, uint8_t qos, List *qosQueue) {
    SubRequester *req = dslink_calloc(1, sizeof(SubRequester));
    if (qosQueue) {
        req->qosQueue = qosQueue;
    } else if (qos & 2){
        req->qosQueue = dslink_malloc(sizeof(List));
        list_init(req->qosQueue);
    }

    req->requester = requester;
    req->reqSid = reqSid;
    req->qos = qos;
    return req;
}

void broker_free_sub_requester(SubRequester *req) {
    if (req->qosQueue) {
        //TODO free content in req->qosQueue

        dslink_free(req->qosQueue);
    }

    dslink_free(req);
}
