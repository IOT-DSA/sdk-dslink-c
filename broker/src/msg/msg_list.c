#include <string.h>

#define LOG_TAG "msg_list"
#include <dslink/log.h>
#include <dslink/ws.h>
#include <dslink/utils.h>

#include "broker/node.h"
#include "broker/stream.h"
#include "broker/msg/msg_list.h"

#define BROKER_CREATE_RESP(rid, stream) \
    json_t *top = json_object(); \
    if (!top) { \
        return NULL; \
    } \
    json_t *resps = json_array(); \
    if (!resps) { \
        json_delete(top); \
        return NULL; \
    } \
    json_t *resp = json_object(); \
    if (!resp) { \
        json_delete(top); \
        json_delete(resps); \
        return NULL; \
    } \
    json_object_set_new_nocheck(top, "responses", resps); \
    json_array_append_new(resps, resp); \
    json_object_set_nocheck(resp, "rid", rid); \
    json_object_set_new_nocheck(resp, "stream", json_string(stream))

static
json_t *broker_list_root(json_t *rid) {
    BROKER_CREATE_RESP(rid, "open");
    json_t *updates = json_array();
    if (!updates) {
        json_delete(top);
        return NULL;
    }
    json_object_set_new_nocheck(resp, "updates", updates);

    {
        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_array_append_new(up, json_string("$is"));
        json_array_append_new(up, json_string("node"));
        json_array_append_new(updates, up);
    }

    {
        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_t *node = json_object();
        if (!node) {
            json_delete(up);
            goto fail;
        }

        json_array_append_new(up, json_string("downstream"));
        json_array_append_new(up, node);

        json_object_set_new(node, "$is", json_string("node"));
        json_array_append_new(updates, up);
    }

    return top;
fail:
    json_delete(top);
    return NULL;
}

static
json_t *broker_list_defs(json_t *rid) {
    BROKER_CREATE_RESP(rid, "open");
    json_t *updates = json_array();
    if (!updates) {
        json_delete(top);
        return NULL;
    }
    json_object_set_new_nocheck(resp, "updates", updates);

    {
        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_array_append_new(up, json_string("$is"));
        json_array_append_new(up, json_string("static"));
        json_array_append_new(updates, up);
    }

    return top;
    fail:
    json_delete(top);
    return NULL;
}

static
json_t *broker_list_downstream(Broker *broker, json_t *rid) {
    BROKER_CREATE_RESP(rid, "open");

    json_t *updates = json_array();
    if (!updates) {
        json_delete(top);
        return NULL;
    }
    json_object_set_new_nocheck(resp, "updates", updates);

    {
        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_array_append_new(up, json_string("$is"));
        json_array_append_new(up, json_string("node"));
        json_array_append_new(updates, up);
    }

    dslink_map_foreach(&broker->downstream) {
        const char *name = ((DownstreamNode *) entry->value)->name;

        json_t *up = json_array();
        if (!up) {
            goto fail;
        }

        json_t *node = json_object();
        if (!node) {
            json_delete(up);
            goto fail;
        }

        json_array_append_new(up, json_string(name));
        json_array_append_new(up, node);

        json_object_set_new(node, "$is", json_string("node"));
        json_array_append_new(updates, up);
    }

    return top;
fail:
    json_delete(top);
    return NULL;
}

static
void broker_list_dslink(Broker *broker,
                        DownstreamNode *node,
                        const char *path,
                        uint32_t reqRid) {
    // TODO: so much error handling
    {
        BrokerListStream *stream = dslink_map_get(&node->link->list_streams,
                                                  (void *) path);
        if (stream) {
            uint32_t *r = malloc(sizeof(uint32_t));
            *r = reqRid;
            void *tmp = broker->link;
            dslink_map_set(&stream->clients, r, &tmp);

            json_t *cached_updates = broker_stream_list_get_cache(stream);
            // TODO: send cached result only when list stream to the responder is running
            // otherwise it should wait for new list to finish to avoid sending outdated data
            if (cached_updates) {
                json_t *top = json_object();
                json_t *resps = json_array();
                json_object_set_new_nocheck(top, "responses", resps);
                json_t *resp = json_object();
                json_array_append_new(resps, resp);

                json_object_set_new_nocheck(resp, "rid", json_integer(reqRid));
                json_object_set_new_nocheck(resp, "stream", json_string("open"));
                json_object_set_new_nocheck(resp, "updates", cached_updates);
                json_decref(cached_updates);

                dslink_ws_send_obj(broker->ws, top);
                json_decref(top);

            }

            return;
        }
    }

    uint32_t rid = 0;
    {
        json_t *top = json_object();
        json_t *reqs = json_array();
        json_object_set_new_nocheck(top, "requests", reqs);

        json_t *req = json_object();
        json_array_append_new(reqs, req);
        json_object_set_new_nocheck(req, "method", json_string("list"));
        json_object_set_new_nocheck(req, "path", json_string(path));

        rid = broker_node_incr_rid(node);
        json_object_set_new_nocheck(req, "rid",
                                    json_integer((json_int_t) rid));

        {
            Socket *prevSock = broker->socket;
            RemoteDSLink *prevLink = broker->link;

            broker->socket = node->link->socket;
            broker->link = node->link;

            dslink_ws_send_obj(broker->ws, top);
            json_delete(top);

            broker->socket = prevSock;
            broker->link = prevLink;
        }
    }
    {
        BrokerListStream *stream = broker_stream_list_init();
        if (strcmp(path, "/") == 0
            && node->link->linkData) {
            // add linkData into the updates_cache
            json_object_set_nocheck(stream->updates_cache, "$linkData", node->link->linkData);
        }


        void *tmp = node->link;
        uint32_t *r = malloc(sizeof(uint32_t));
        *r = reqRid;
        dslink_map_set(&stream->clients, r, &tmp);

        r = malloc(sizeof(uint32_t));
        *r = rid;
        tmp = stream;
        dslink_map_set(&node->link->local_streams, r, &tmp);

        char *p = dslink_strdup(path);
        tmp = stream;
        dslink_map_set(&node->link->list_streams, p, &tmp);
    }
}

int broker_msg_handle_list(Broker *broker, json_t *req) {
    const char *path = json_string_value(json_object_get(req, "path"));
    json_t *rid = json_object_get(req, "rid");
    if (!(path && rid)) {
        return 1;
    }

    json_t *resp = NULL;
    if (strcmp(path, "/") == 0) {
        resp = broker_list_root(rid);
    } else if (strncmp(path, "/defs/", 5) == 0) {
        resp = broker_list_defs(rid);
    } else if (strcmp(path, "/downstream") == 0) {
        resp = broker_list_downstream(broker, rid);
    } else if (dslink_str_starts_with(path, "/downstream/")) {
        const char *name = path + sizeof("/downstream/") - 1;
        const char *linkPath;
        size_t nameLen = strlen(name);
        {
            const char *loc = strchr(name, '/');
            if (loc) {
                nameLen = strlen(loc);
                linkPath = loc;
            } else {
                linkPath = "/";
            }
        }
        DownstreamNode *node = dslink_map_getl(&broker->downstream,
                                               (void *) name, nameLen);
        if (node) {
            uint32_t reqRid = (uint32_t) json_integer_value(rid);
            broker_list_dslink(broker, node, linkPath, reqRid);
            goto success;
        }
    } else {
        log_err("Unhandled path: %s\n", path);
    }

    if (!resp) {
        return 1;
    }
    dslink_ws_send_obj(broker->ws, resp);
    json_decref(resp);
success:
    return 0;
}
