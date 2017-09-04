#define LOG_TAG "msg_handler"
#include <dslink/log.h>

#include <string.h>
#include <broker/subscription.h>
#include <broker/msg/msg_remove.h>
#include "broker/msg/msg_set.h"
#include "broker/msg/msg_unsubscribe.h"
#include "broker/msg/msg_subscribe.h"
#include "broker/msg/msg_invoke.h"
#include "broker/msg/msg_handler.h"
#include "broker/msg/msg_list.h"
#include "broker/net/ws.h"

static
int broker_msg_handle_close(RemoteDSLink *link, json_t *req) {
    json_t *jRid = json_object_get(req, "rid");
    if (!json_is_integer(jRid)) {
        return 1;
    }
    uint32_t rid = (uint32_t) json_integer_value(jRid);

    ref_t *ref = dslink_map_remove_get(&link->requester_streams, &rid);

    if (ref && ref->data) {
        requester_stream_closed(ref->data, link);
        dslink_decref(ref);
    }
    return 0;
}

static
void broker_handle_req(RemoteDSLink *link, json_t *req) {
    // Firstly check rid
    json_t *jRid = json_object_get(req, "rid");
    if (!jRid) { return; }
    uint32_t rid = (uint32_t) json_integer_value(jRid);

    //printf("%s\n", json_dumps(req, JSON_INDENT(1)));// dev debug


    const char *method = json_string_value(json_object_get(req, "method"));
    ref_t *ref = dslink_map_get(&link->requester_streams, &rid);
    if (ref && !method) {
        BrokerInvokeStream *stream = ref->data;
        if (stream->continuous_invoke) {
            json_t *params = json_object_get(req, "params");
            stream->continuous_invoke(link,  params);
        }
        return;
    }



    // Front permission check with possible lowest permission (PERMISSION_LIST)
    const char *path = json_string_value(json_object_get(req, "path"));
    if(path)
    {
        if(!security_barrier(link, req, path, PERMISSION_LIST, NULL))
            return;
    }

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
    } else if (strcmp(method, "subscribe") == 0) {
        if (broker_msg_handle_subscribe(link, req) != 0) {
            log_err("Failed to handle subscribe request\n");
        }
    } else if (strcmp(method, "unsubscribe") == 0) {
        if (broker_msg_handle_unsubscribe(link, req) != 0) {
            log_err("Failed to handle unsubscribe request\n");
        }
    } else if (strcmp(method, "set") == 0) {
        if (broker_msg_handle_set(link, req) != 0) {
            log_err("Failed to handle set request");
        }
    } else if (strcmp(method, "remove") == 0) {
        if (broker_msg_handle_remove(link, req) != 0) {
            log_err("Failed to handle remove request");
        }
    } else if (strcmp(method, "close") == 0) {
        if (broker_msg_handle_close(link, req) != 0) {
            log_err("Failed to handle close request\n");
        }
    } else {
        log_err("Method unhandled: %s\n", method);
    }
}

static
void broker_handle_resp(RemoteDSLink *link, json_t *resp) {
    json_t *jRid = json_object_get(resp, "rid");
    if (!jRid) {
        return;
    }
    uint32_t rid = (uint32_t) json_integer_value(jRid);

    if (rid == 0) {
        size_t index;
        json_t *update;

        //Updates are not sent directly, first collected for each link then sent
        dslink_map_foreach(&link->broker->remote_connected) {
            RemoteDSLink* connLink = (RemoteDSLink*)entry->value->data;
            if(connLink->updates)
                json_delete(connLink->updates);

        }

        json_array_foreach(json_object_get(resp, "updates"), index, update) {
            if(!link->node)
                continue;

            if (json_is_array(update)) {
                json_t *jSid = json_array_get(update, 0);
                if (!jSid) {
                    continue;
                }
                uint32_t sid = (uint32_t) json_integer_value(jSid);
                ref_t *ref = dslink_map_get(&link->node->resp_sub_sids, &sid);
                if (!ref) {
                    continue;
                }

                BrokerSubStream *s = ref->data;
                broker_update_sub_stream(s, update,0);
            } else if (json_is_object(update)) {
                json_t *jSid = json_object_get(update, "sid");
                if (!jSid) {
                    continue;
                }
                uint32_t sid = (uint32_t) json_integer_value(jSid);
                ref_t *ref = dslink_map_get(&link->node->resp_sub_sids, &sid);
                if (!ref) {
                    continue;
                }

                BrokerSubStream *s = ref->data;
                json_t *value = json_object_get(update, "value");
                json_t *ts = json_object_get(update, "ts");
                broker_update_sub_stream_value(s, value, ts);
            }

        }

        //Updates are not sent directly, first collected for each link then sent
        dslink_map_foreach(&link->broker->remote_connected) {
            RemoteDSLink *connLink = (RemoteDSLink *) entry->value->data;
            if (connLink->updates) {

                json_t *top = json_object();
                json_t *resps = json_array();
                json_object_set_new_nocheck(top, "responses", resps);
                json_t *newResp = json_object();
                json_array_append_new(resps, newResp);
                json_object_set_new_nocheck(newResp, "rid", json_integer(0));
                json_object_set_new_nocheck(newResp, "updates", connLink->updates);

                broker_ws_send_obj(connLink, top, BROKER_MESSAGE_DROPPABLE);
                json_decref(top);
                connLink->updates = NULL;
            }
        }
        return;
    }

    ref_t *ref = dslink_map_get(&link->responder_streams, &rid);
    if (!ref) {
        return;
    }

    BrokerStream *stream = ref->data;
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
        broker_ws_send_obj(is->requester, top, BROKER_MESSAGE_DROPPABLE);
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
    if (!data) { return; }
    json_incref(data);

    json_t *ack = json_object_get(data, "ack");
    if(ack && json_is_integer(ack)) {
        log_debug("Received ack for msg %d\n", (uint32_t)json_integer_value(ack));
    }

    json_t *reqs = json_object_get(data, "requests");
    json_t *resps = json_object_get(data, "responses");

    if (reqs || resps) {
        json_t *msg = json_object_get(data, "msg");
        if (json_is_integer(msg)) {
            json_t *obj = json_object();
            if (obj) {
                json_object_set_nocheck(obj, "ack", msg);
                broker_ws_send_obj(link, obj, BROKER_MESSAGE_DROPPABLE);
                json_decref(obj);
            }
        }
    }

    if (link && link->isResponder && resps) {
        json_t *resp;
        size_t index = 0;
        json_array_foreach(resps, index, resp) {
            broker_handle_resp(link, resp);
        }
    }


    if (link && link->isRequester && reqs) {
        json_t *req;
        size_t index = 0;
        json_array_foreach(reqs, index, req) {
            broker_handle_req(link, req);
        }
    }

    json_decref(data);

}
