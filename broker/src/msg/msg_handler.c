#define LOG_TAG "msg_handler"
#include <dslink/log.h>

#include <string.h>
#include <dslink/ws.h>
#include "broker/msg/msg_handler.h"
#include <broker/msg/msg_list.h>
#include <broker/stream.h>

static
void broker_handle_req(Broker *broker, json_t *req) {
    const char *method = json_string_value(json_object_get(req, "method"));
    if (!method) {
        return;
    }
    if (strcmp(method, "list") == 0) {
        if (broker_msg_handle_list(broker, req) != 0) {
            log_err("Failed to handle list request\n");
        }
    } else {
        log_err("Method unspecified: %s\n", method);
    }
}

static
void broker_handle_resp(Broker *broker, json_t *resp) {
    // TODO: error handling
    json_t *jRid = json_object_get(resp, "rid");
    if (!jRid) {
        return;
    }

    uint32_t rid = (uint32_t) json_integer_value(jRid);
    Stream *stream = dslink_map_get(&broker->link->local_streams,
                                    &rid);
    if (!stream) {
        return;
    }

    if (stream->type == LIST_STREAM) {
        BrokerListStream *ls = (BrokerListStream *) stream;
        // TODO: handle the updates cache for base and updates/removals
        ls->updates_cache = json_object_get(resp, "updates");
        json_incref(ls->updates_cache);

        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_array_append(resps, resp);
        dslink_map_foreach(&ls->clients) {
            json_object_del(resp, "rid");
            json_t *newRid = json_integer(*((uint32_t *) entry->key));
            json_object_set_new_nocheck(resp, "rid", newRid);

            Socket *prevSock = broker->socket;
            RemoteDSLink *prevLink = broker->link;

            RemoteDSLink *client = entry->value;
            broker->socket = client->socket;
            broker->link = client;
            dslink_ws_send_obj(broker->ws, top);

            broker->socket = prevSock;
            broker->link = prevLink;
        }
        json_decref(top);
    }
}

void broker_msg_handle(Broker *broker,
                       json_t *data) {
    if (!data) {
        return;
    }
    json_incref(data);

    {
        json_t *reqs = json_object_get(data, "requests");
        if (broker->link->isRequester && reqs) {
            json_t *req;
            size_t index = 0;
            json_array_foreach(reqs, index, req) {
                broker_handle_req(broker, req);
            }
        }
    }

    {
        json_t *resps = json_object_get(data, "responses");
        if (broker->link->isResponder && resps) {
            json_t *resp;
            size_t index = 0;
            json_array_foreach(resps, index, resp) {
                broker_handle_resp(broker, resp);
            }
        }
    }

    json_decref(data);
}
