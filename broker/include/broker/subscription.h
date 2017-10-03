#ifndef SDK_BROKER_SUBSCRIPTION_H
#define SDK_BROKER_SUBSCRIPTION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <broker/stream.h>
#include <broker/node.h>

#include <dslink/col/vector.h>
#include <dslink/col/ringbuffer.h>


typedef struct SubRequester {
    char *path;
    DownstreamNode *reqNode;
    BrokerSubStream *stream;
    uint32_t reqSid;
    uint8_t qos;
    json_t *qosQueue;
    char *qosKey1;
    char *qosKey2;
    // pending list node
    ListNode *pendingNode;
    Ringbuffer* messageQueue;
    uint32_t messageOutputQueueCount;
} SubRequester;


typedef struct PendingAck {
    SubRequester* subscription;
    uint32_t msg_id;
} PendingAck;

typedef struct QueuedMessage {
    json_t* message;
    uint32_t msg_id;
} QueuedMessage;


void send_subscribe_request(DownstreamNode *node,
                            const char *path,
                            uint32_t sid,
                            uint8_t qos);


SubRequester *broker_create_sub_requester(DownstreamNode * node, const char *path, uint32_t reqSid, uint8_t qos, json_t *qosQueue);
void broker_free_sub_requester(SubRequester *req);
void broker_clear_messsage_ids(SubRequester *req);

int sendQueuedMessages(SubRequester *subReq);

void clear_qos_queue(SubRequester *subReq, uint8_t serialize);

void broker_update_sub_req_qos(SubRequester *subReq);
int broker_update_sub_req(SubRequester *subReq, json_t *varray);

int broker_update_sub_stream(BrokerSubStream *stream, json_t *array, json_t *responder_msg_id);
int broker_update_sub_stream_value(BrokerSubStream *stream, json_t *value, json_t *ts, json_t *responder_msg_id);

void broker_update_stream_qos(BrokerSubStream *stream);
void broker_update_sub_qos(SubRequester *req, uint8_t qos);
void serialize_qos_queue(SubRequester *subReq, uint8_t delete);

int check_subscription_ack(RemoteDSLink *link, uint32_t ack);

#ifdef __cplusplus
}
#endif


#endif //SDK_BROKER_SUBSCRIPTION_H
