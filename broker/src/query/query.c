#include "broker/net/ws.h"
#include <string.h>
#include "broker/stream.h"
#include "broker/msg/msg_invoke.h"
#include "broker/query/query.h"

typedef struct ParsedQuery {
    char *pattern;
} ParsedQuery;


typedef enum { NOT_MATCH, PARTIAL_MATCH, MATCH} MatchResult;

static
MatchResult match_query(const char *path, const char *pattern) {
    while (*path != '\0' && *pattern != '\0') {
        while (*path == *pattern) {
            path++;
            pattern++;
        }
        if (*pattern == '?') {
            ++pattern;
            while (*path != '/') {
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
            if (*path == '\0') {
                return PARTIAL_MATCH;
            }
            return NOT_MATCH;
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


int query_child_added(BrokerInvokeStream *stream, BrokerNode *node) {
    ParsedQuery *pQuery = stream->data;
    if (pQuery && node) {
        MatchResult rslt = match_query(node->path, pQuery->pattern);
        if (rslt == MATCH || rslt == PARTIAL_MATCH) {

        }
        if (rslt == MATCH) {

        }
    }
    return 0;
}
int query_child_removed(BrokerInvokeStream *stream, BrokerNode *node) {
    ParsedQuery *pQuery = stream->data;
    if (pQuery && node) {

    }
    return 0;
}
int query_value_update(BrokerInvokeStream *stream, BrokerNode *node) {
    ParsedQuery *pQuery = stream->data;
    if (pQuery && node) {

    }
    return 0;
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

    char *path = malloc(pathLen + 1);
    memcpy(path, pathstart, pathLen);
    path[pathLen] = 0;
    ParsedQuery *pQuery = malloc(sizeof(ParsedQuery));
    pQuery->pattern = path;
    return pQuery;
}



static void start_query_stream(BrokerInvokeStream *stream, ParsedQuery *pQuery) {
    if (stream && pQuery) {

    }
}

static
void query_invoke(struct RemoteDSLink *link,
                         struct BrokerNode *node,
                         json_t *request) {
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

        start_query_stream(stream, pQuery);

        uint32_t *r = malloc(sizeof(uint32_t));
        *r = stream->requester_rid;
        dslink_map_set(&link->requester_streams, r, (void **) &stream);

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
    if (!node || broker_node_add(parent, node) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$invokable",
                            json_string("write")) != 0) {
        broker_node_free(node);
        return NULL;
    }

    if (json_object_set_new(node->meta, "$result",
                            json_string("stream")) != 0) {
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

    node->on_invoke = query_invoke;

    return node;
fail:
    broker_node_free(node);
    json_decref(paramList);
    return NULL;
}
