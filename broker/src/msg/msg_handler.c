#define LOG_TAG "msg_handler"
#include <dslink/log.h>

#include <string.h>
#include "broker/msg/msg_invoke.h"
#include "broker/msg/msg_handler.h"
#include "broker/msg/msg_list.h"
#include "broker/stream.h"
#include "broker/net/ws.h"

static
void broker_handle_req(RemoteDSLink *link, json_t *req) {
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
    BrokerStream *stream = dslink_map_get(&link->local_streams,
                                    &rid);
    if (!stream) {
        return;
    }

    if (stream->type == LIST_STREAM) {
        BrokerListStream *ls = (BrokerListStream *) stream;
        json_t *updates = json_object_get(resp, "updates");
        if (json_is_array(updates)) {
            size_t i;
            json_t *child;
            uint8_t cache_need_reset = 1;
            json_array_foreach(updates, i, child) {
                // update cache
                if(json_is_array(child)) {
                    json_t *childName = json_array_get(child, 0);
                    json_t *childValue = json_array_get(child, 1);
                    if (childName->type == JSON_STRING) {
                        const char *name = json_string_value(childName);
                        if (strcmp(name, "$base") == 0) {
                            // clear cache when $base or $is changed
                            if (cache_need_reset) {
                                broker_stream_list_reset_remote_cache(ls, link);
                                cache_need_reset = 0;
                            }
                            const char *originalBase = json_string_value(childValue);
                            if (originalBase) {
                                char buff[512];
                                strcpy(buff, ((BrokerListStream *) stream)->remotePath);
                                strcat(buff, "/");
                                strcat(buff, originalBase);
                                json_object_set_new_nocheck(
                                        ls->updates_cache, "$base",
                                        json_string_nocheck(buff));
                            }
                            continue; // already added to cache
                        }
                        if (strcmp(name, "$is") == 0) {
                            // clear cache when $base or $is changed
                            if (cache_need_reset) {
                                broker_stream_list_reset_remote_cache(ls, link);
                                cache_need_reset = 0;
                            }
                        }
                        json_object_set_nocheck(ls->updates_cache,
                                                name, childValue);
                    }
                } else if (json_is_object(child)) {
                    json_t *childName = json_object_get(child, "name");
                    json_t *change = json_object_get(child, "change");
                    if (json_is_string(childName) && json_is_string(change)
                        && strcmp(json_string_value(change),"remove") == 0) {
                        json_object_del(ls->updates_cache,
                                        json_string_value(childName));
                    } else {
                        // a list value update? almost never used
                    }
                }
            }
        }

        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_array_append(resps, resp);
        dslink_map_foreach(&ls->clients) {
            json_object_del(resp, "rid");
            json_t *newRid = json_integer(*((uint32_t *) entry->key));
            json_object_set_new_nocheck(resp, "rid", newRid);

            RemoteDSLink *client = entry->value;
            broker_ws_send_obj(client, top);
        }
        json_decref(top);
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

    {
        json_t *reqs = json_object_get(data, "requests");
        if (link->isRequester && reqs) {
            json_t *req;
            size_t index = 0;
            json_array_foreach(reqs, index, req) {
                broker_handle_req(link, req);
            }
        }
    }

    {
        json_t *resps = json_object_get(data, "responses");
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
