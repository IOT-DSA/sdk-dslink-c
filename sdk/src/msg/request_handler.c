#include <jansson.h>
#include <string.h>

#include "dslink/msg/request_handler.h"
#include "dslink/msg/list_response.h"
#include "dslink/msg/sub_response.h"

#define LOG_TAG "request_handler"
#include "dslink/log.h"

int dslink_request_handle(DSLink *link, json_t *req) {
    const char *method = json_string_value(json_object_get(req, "method"));
    if (!method) {
        return 1;
    }

    if (strcmp(method, "list") == 0) {
        const char *path = json_string_value(json_object_get(req, "path"));
        DSNode *node = dslink_node_get_path(link->responder->super_root, path);
        return dslink_response_list(link, req, node);
    } else if (strcmp(method, "subscribe") == 0) {
        json_t *paths = json_object_get(req, "paths");
        json_t *rid = json_object_get(req, "rid");
        return dslink_response_sub(link, paths, rid);
    } else if (strcmp(method, "unsubscribe") == 0) {
        json_t *sids = json_object_get(req, "sids");
        json_t *rid = json_object_get(req, "rid");
        return dslink_response_unsub(link, sids, rid);
    } else if (strcmp(method, "invoke") == 0) {
        const char *path = json_string_value(json_object_get(req, "path"));
        DSNode *node = dslink_node_get_path(link->responder->super_root, path);
        if (node && node->on_invocation) {
            json_t *rid = json_object_get(req, "rid");
            json_t *params = json_object_get(req, "params");
            node->on_invocation(link, node, rid, params);
        }
    } else if (strcmp(method, "close") == 0) {
        uint32_t rid = (uint32_t) json_integer_value(
                                    json_object_get(req, "rid"));
        dslink_map_remove(link->responder->open_streams, &rid);
        /*if (s) {
            dslink_free(p);
            switch (s->type) {
                case LIST_STREAM:
                    p = (void *) s->path;
                    dslink_map_remove(link->responder->list_subs, &p);
                    break;
                case INVALID_STREAM: default:
                    break;
            }
            if (s->on_close) {
                DSNode *node = link->responder->super_root;
                node = dslink_node_get_path(node, s->path);
                if (node) {
                    s->on_close(link, node);
                }
            }
            dslink_free(s);
        }*/
    } else {
        log_warn("Unrecognized method: %s\n", method);
    }
    return 0;
}
