#include <broker/sys/throughput.h>

#include <broker/node.h>
#include <broker/stream.h>
#include <broker/broker.h>

static BrokerNode *messagesOutPerSecond;
static BrokerNode *dataOutPerSecond;
static BrokerNode *frameOutPerSecond;

static BrokerNode *messagesInPerSecond;
static BrokerNode *dataInPerSecond;
static BrokerNode *frameInPerSecond;

static int outframes = -1;
static int outbytes = 0;
static int outmessages = 0;

static int inframes = -1;
static int inbytes = 0;
static int inmessages = 0;

static uv_timer_t throughputTimer;

static void onThroughputTimer(uv_timer_t *handle) {
    (void) handle;
    if (inframes >= 0) {
        int t = inframes; inframes = 0;
        broker_node_update_value(frameInPerSecond, json_integer(t), 1);

        t = inbytes; inbytes = 0;
        broker_node_update_value(dataInPerSecond, json_integer(t), 1);

        t = inmessages; inmessages = 0;
        broker_node_update_value(messagesInPerSecond, json_integer(t), 1);
    }
    if (outframes >= 0) {
        int t = outframes; outframes = 0;
        broker_node_update_value(frameOutPerSecond, json_integer(t), 1);

        t = outbytes; outbytes = 0;
        broker_node_update_value(dataOutPerSecond, json_integer(t), 1);

        t = outmessages; outmessages = 0;
        broker_node_update_value(messagesOutPerSecond, json_integer(t), 1);
    }
}

int init_throughput(struct BrokerNode *sysNode) {
    messagesOutPerSecond = broker_node_create("messagesOutPerSecond", "node");
    json_object_set(messagesOutPerSecond->meta, "$type", json_string_nocheck("number"));
    broker_node_add(sysNode, messagesOutPerSecond);

    dataOutPerSecond = broker_node_create("dataOutPerSecond", "node");
    json_object_set(dataOutPerSecond->meta, "$type", json_string_nocheck("number"));
    json_object_set(dataOutPerSecond->meta, "@unit", json_string_nocheck("bytes"));
    broker_node_add(sysNode, dataOutPerSecond);

    frameOutPerSecond = broker_node_create("frameOutPerSecond", "node");
    json_object_set(frameOutPerSecond->meta, "$type", json_string_nocheck("number"));
    broker_node_add(sysNode, frameOutPerSecond);

    messagesInPerSecond = broker_node_create("messagesInPerSecond", "node");
    json_object_set(messagesInPerSecond->meta, "$type", json_string_nocheck("number"));
    broker_node_add(sysNode, messagesInPerSecond);

    dataInPerSecond = broker_node_create("dataInPerSecond", "node");
    json_object_set(dataInPerSecond->meta, "$type", json_string_nocheck("number"));
    json_object_set(dataInPerSecond->meta, "@unit", json_string_nocheck("bytes"));
    broker_node_add(sysNode, dataInPerSecond);

    frameInPerSecond = broker_node_create("frameInPerSecond", "node");
    json_object_set(frameInPerSecond->meta, "$type", json_string_nocheck("number"));
    broker_node_add(sysNode, frameInPerSecond);

    uv_timer_init(mainLoop, &throughputTimer);
    uv_timer_start(&throughputTimer, onThroughputTimer, 1000, 1000);
    return 0;
}


int throughput_input_needed() {
    if (messagesInPerSecond->sub_stream) {
        return 1;
    }
    if (dataInPerSecond->sub_stream) {
        return 1;
    }
    if (frameInPerSecond->sub_stream) {
        return 1;
    }
    inframes = -1;
    return 0;
}

void throughput_add_input(int bytes, int messages) {
    if (inframes < 0) {
        inframes = 1;
    } else {
        inframes++;
    }
    inbytes += bytes;
    inmessages += messages;
}


int throughput_output_needed() {
    if (messagesOutPerSecond->sub_stream) {
        return 1;
    }
    if (dataOutPerSecond->sub_stream) {
        return 1;
    }
    if (frameOutPerSecond->sub_stream) {
        return 1;
    }
    outframes = -1;
    return 0;
}

void throughput_add_output(int bytes, int messages) {
    if (outframes < 0) {
        outframes = 1;
    } else {
        outframes++;
    }
    outbytes += bytes;
    outmessages += messages;
}

