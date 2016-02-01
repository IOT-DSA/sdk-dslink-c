#define LOG_TAG "msg_handler"
#include <dslink/log.h>

#include <string.h>
#include "broker/msg/msg_invoke.h"
#include "broker/msg/msg_handler.h"
#include "broker/msg/msg_list.h"
#include "broker/net/ws.h"

static
void broker_handle_req(RemoteDSLink *link, json_t *req) {
    json_t *jRid = json_object_get(req, "rid");
    if (!jRid) {
        return;
    }

    uint32_t r = (uint32_t) json_integer_value(jRid);
    BrokerInvokeStream *stream = dslink_map_get(&link->requester_streams, &r);
    if (stream) {
        if (stream->continuous_invoke) {
            json_t *params = json_object_get(req, "params");
            stream->continuous_invoke(link,  params);
        }
        return;
    }

    const char *method = json_string_value(json_object_get(req, "method"));
    if (!method) {
        return;
    }
    if (strcmp(method, "list") == 0) {
        if (broker_msg_handle_list(link, req) != 0) {
            log_err("Failed to handle list request\n");
        }
    } else if (strcmp(method, "invoke") == 0) {
        if (broker_msg_handle_invoke(link, req) != 0) {
            log_err("Failed handle invocation request\n");
        }
    } else {
        log_err("Method unhandled: %s\n", method);
    }
}

static
void broker_handle_resp(RemoteDSLink *link, json_t *resp) {
    // TODO: error handling
    json_t *jRid = json_object_get(resp, "rid");
    if (!jRid) {
        return;
    }

    uint32_t rid = (uint32_t) json_integer_value(jRid);
    BrokerStream *stream = dslink_map_get(&link->responder_streams,
                                    &rid);
    if (!stream) {
        return;
    }

    if (stream->type == LIST_STREAM) {
        broker_list_dslink_response(link, resp, (BrokerListStream *) stream);
    } else if (stream->type == INVOCATION_STREAM) {
        BrokerInvokeStream *is = (BrokerInvokeStream *) stream;
        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_array_append(resps, resp);

        json_t *newRid = json_integer(is->requester_rid);
        json_object_set_new_nocheck(resp, "rid", newRid);
        broker_ws_send_obj(is->requester, top);
        json_decref(top);

        json_t *jStreamStat = json_object_get(resp, "stream");
        if (json_is_string(jStreamStat)) {
            const char *streamStat = json_string_value(jStreamStat);
            if (strcmp(streamStat, "closed") == 0) {
                broker_stream_free(stream);
            }
        }
    }
}

void broker_msg_handle(RemoteDSLink *link,
                       json_t *data) {
    if (!data) {
        return;
    }
    json_incref(data);

    json_t *reqs = json_object_get(data, "requests");
    json_t *resps = json_object_get(data, "responses");

    if (reqs || resps) {
        json_t *msg = json_object_get(data, "msg");
        if (json_is_integer(msg)) {
            json_t *obj = json_object();
            if (obj) {
                json_object_set_nocheck(obj, "ack", msg);
                broker_ws_send_obj(link, obj);
            }
        }
    }

    {
        if (link->isRequester && reqs) {
            json_t *req;
            size_t index = 0;
            json_array_foreach(reqs, index, req) {
                broker_handle_req(link, req);
            }
        }
    }

    {
        if (link->isResponder && resps) {
            json_t *resp;
            size_t index = 0;
            json_array_foreach(resps, index, resp) {
                broker_handle_resp(link, resp);
            }
        }
    }

    json_decref(data);
}
