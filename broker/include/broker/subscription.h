#ifndef SDK_BROKER_SUBSCRIPTION_H
#define SDK_BROKER_SUBSCRIPTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <broker/stream.h>
#include <broker/node.h>

typedef struct SubRequester {
    char *path;
    DownstreamNode *reqNode;
    DownstreamNode *respNode;
    BrokerSubStream *stream;
    uint32_t reqSid;
    uint8_t qos;
    json_t *qosQueue;
    char *qosKey1;
    char *qosKey2;
    // pending list node
    ListNode *pendingNode;
} SubRequester;

void send_subscribe_request(DownstreamNode *node,
                            const char *path,
                            uint32_t sid,
                            uint8_t qos);

SubRequester *broker_create_sub_requester(DownstreamNode * node, const char *path, uint32_t reqSid, uint8_t qos, json_t *qosQueue);
void broker_free_sub_requester(SubRequester *req);

void clear_qos_queue(SubRequester *subReq, uint8_t serialize);

void broker_update_sub_req_qos(SubRequester *subReq);
void broker_update_sub_req(SubRequester *subReq, json_t *varray);

void broker_update_sub_stream(BrokerSubStream *stream, json_t *array);
void broker_update_sub_stream_value(BrokerSubStream *stream, json_t *value, json_t *ts);

void broker_update_stream_qos(BrokerSubStream *stream);
void broker_update_sub_qos(SubRequester *req, uint8_t qos);
void serialize_qos_queue(SubRequester *subReq, uint8_t delete);

#ifdef __cplusplus
}
#endif


#endif //SDK_BROKER_SUBSCRIPTION_H
