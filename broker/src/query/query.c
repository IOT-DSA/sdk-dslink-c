#include <string.h>
#include <dslink/utils.h>
#include <dslink/mem/mem.h>

#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/stream.h"
#include "broker/msg/msg_invoke.h"
#include "broker/query/query.h"

typedef struct ParsedQuery {
    char *pattern;
    Map child_add_listeners;
    Map value_update_listeners;
} ParsedQuery;

typedef enum {
    NOT_MATCH,
    PARTIAL_MATCH,
    MATCH
} MatchResult;

static
MatchResult match_query(const char *path, const char *pattern) {
    while (*path != '\0' && *pattern != '\0') {
        while (*pattern && *path == *pattern) {
            path++;
            pattern++;
        }

        if (*pattern == '?') {
            ++pattern;
            while (*path != '/' && *path != '\0') {
                ++path;
            }
        } else if (*pattern == '*') {
            ++pattern;
            if (*pattern == '\0') {
                return MATCH;
            }
            MatchResult bestMatch = NOT_MATCH;
            while (*path != '\0') {
                if (*path == *pattern) {
                    MatchResult newMatch = match_query(path, pattern);
                    if (newMatch == MATCH) {
                        return MATCH;
                    }
                    if (newMatch == PARTIAL_MATCH) {
                        bestMatch = PARTIAL_MATCH;
                    }
                }
                ++path;
            }
            return bestMatch;
        } else {
            break;
        }
    }

    if (*path == '\0') {
        if (*pattern == '\0') {
            return MATCH;
        } else {
            return PARTIAL_MATCH;
        }
    }
    return NOT_MATCH;
}

int query_value_update(Listener *listener, void *node) {
    BrokerInvokeStream *stream = listener->data;
    ParsedQuery *pQuery = stream->data;
    if (pQuery && node) {
        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_t *resp = json_object();
        json_array_append_new(resps, resp);

        json_object_set_new_nocheck(resp, "rid",
            json_integer(stream->requester_rid));

        json_t *updates = json_array();

        json_t *update = json_array();

        json_array_append_new(update, json_string_nocheck(((BrokerNode*)node)->path));
        json_array_append_new(update, json_string_nocheck(""));
        json_array_append(update, ((BrokerNode*)node)->value);
        char ts[32];
        dslink_create_ts(ts, 32);
        json_array_append_new(update, json_string_nocheck(ts));

        json_array_append_new(updates, update);

        json_object_set_new_nocheck(resp, "updates", updates);

        broker_ws_send_obj(stream->requester, top);
        json_decref(top);
    }
    return 0;
}

int query_child_removed(Listener *listener, void *node) {
    BrokerInvokeStream *stream = listener->data;
    ParsedQuery *pQuery = stream->data;
    if (pQuery && node) {
        //TODO ?
    }
    return 0;
}
int query_child_added(Listener *listener, void *node);

int query_child_added_stream(BrokerInvokeStream *stream, BrokerNode *node) {

    ParsedQuery *pQuery = stream->data;
    if (pQuery && node) {
        MatchResult rslt = match_query(node->path, pQuery->pattern);
        if (rslt == MATCH || rslt == PARTIAL_MATCH) {
            Listener * listener = listener_add(&node->on_child_added, query_child_added, stream);
            dslink_map_set(&pQuery->child_add_listeners, dslink_str_ref(node->path), dslink_ref(listener, NULL));
            dslink_map_foreach(node->children) {
                BrokerNode* child = entry->value->data;
                query_child_added_stream(stream, child);
            }
        }
        if (rslt == MATCH) {
            Listener * listener = listener_add(&node->on_value_update, query_value_update, stream);
            dslink_map_set(&pQuery->value_update_listeners, dslink_str_ref(node->path), dslink_ref(listener, NULL));
        }
    }
    return 0;
}

int query_child_added(Listener *listener, void *node) {
    return query_child_added_stream((BrokerInvokeStream *)listener->data, (BrokerNode*)node);
}

ParsedQuery *parse_query(const char * query) {
    const char *pos = strchr(query, ' ');
    if (!(pos && strncmp(query, "list", pos - query) == 0)) {
        return NULL;
    }

    query = ++pos;
    const char *pathstart = query;
    size_t pathLen = 0;
    pos = strchr(query, '|');
    if (!pos) {
        return NULL;
    }
    pathLen = pos - pathstart;

    char *path = dslink_malloc(pathLen + 1);
    memcpy(path, pathstart, pathLen);
    path[pathLen] = 0;
    ParsedQuery *pQuery = dslink_malloc(sizeof(ParsedQuery));
    pQuery->pattern = path;

    dslink_map_init(&pQuery->child_add_listeners, dslink_map_str_cmp,
                    dslink_map_str_key_len_cal, dslink_map_hash_key);
    dslink_map_init(&pQuery->value_update_listeners, dslink_map_str_cmp,
                    dslink_map_str_key_len_cal, dslink_map_hash_key);

    return pQuery;
}

int query_destroy(void *s, RemoteDSLink *link) {
    (void) link;
    BrokerInvokeStream *stream = s;
    ParsedQuery *pQuery = stream->data;

    dslink_map_foreach(&pQuery->child_add_listeners) {
        Listener *listener = entry->value->data;
        listener_remove(listener);
        dslink_free(listener);
    }
    dslink_map_free(&pQuery->child_add_listeners);

    dslink_map_foreach(&pQuery->value_update_listeners) {
        Listener *listener = entry->value->data;
        listener_remove(listener);
        dslink_free(listener);
    }
    dslink_map_free(&pQuery->value_update_listeners);

    return 1;
}

static
void query_invoke(struct RemoteDSLink *link,
                         struct BrokerNode *node,
                         json_t *request, PermissionLevel maxPermission) {
    (void)maxPermission;
    if (link && node && request) {
        json_t *params = json_object_get(request, "params");
        if (!json_is_object(params)) {
            goto exit_with_error;
        }

        const char *query = json_string_value(json_object_get(params, "query"));
        if (!query) {
            goto exit_with_error;
        }
        ParsedQuery *pQuery = parse_query(query);
        if (!pQuery) {
            goto exit_with_error;
        }
        BrokerInvokeStream *stream = broker_stream_invoke_init();
        stream->data = pQuery;
        stream->requester = link;
        stream->requester_rid = (uint32_t) json_integer_value(json_object_get(request, "rid"));

        dslink_map_set(&link->requester_streams, dslink_int_ref(stream->requester_rid),
                       dslink_ref(stream, NULL));
        stream->req_close_cb = query_destroy;

        {
            json_t *top = json_object();
            json_t *resps = json_array();
            json_object_set_new_nocheck(top, "responses", resps);
            json_t *resp = json_object();
            json_array_append_new(resps, resp);

            json_t *rid = json_object_get(request, "rid");
            json_object_set(resp, "rid", rid);
            json_object_set_new_nocheck(resp, "stream",
                                        json_string_nocheck("open"));

            broker_ws_send_obj(link, top);
            json_decref(top);
        }
        query_child_added_stream(stream, link->broker->data);
    }
    return;

exit_with_error:
    {
        json_t *top = json_object();
        json_t *resps = json_array();
        json_object_set_new_nocheck(top, "responses", resps);
        json_t *resp = json_object();
        json_array_append_new(resps, resp);

        json_t *rid = json_object_get(request, "rid");
        json_object_set(resp, "rid", rid);
        json_object_set_new_nocheck(resp, "stream",
                                    json_string_nocheck("closed"));

        broker_ws_send_obj(link, top);
        json_decref(top);
    }
}

BrokerNode *broker_query_create_action(BrokerNode *parent) {
    BrokerNode *node = broker_node_create("query", "node");
    if (!node) {
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string_nocheck("write")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$result",
                            json_string_nocheck("stream")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    json_t *paramList = json_array();
    if (broker_invoke_create_param(paramList, "query", "string") != 0
        || json_object_set_new(node->meta, "$params", paramList) != 0) {
        goto fail;
    }

    json_t *columnList = json_array();
    if (broker_invoke_create_param(columnList, "path", "string") != 0
        || broker_invoke_create_param(columnList, "change", "string") != 0
        || broker_invoke_create_param(columnList, "value", "dynamic") != 0
        || broker_invoke_create_param(columnList, "ts", "string") != 0
        || json_object_set_new(node->meta, "$columns", columnList) != 0) {
        goto fail;
    }

    if (broker_node_add(parent, node) != 0) {
        goto fail;
    }

    node->on_invoke = query_invoke;

    return node;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return NULL;
}
