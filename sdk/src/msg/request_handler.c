#include <jansson.h>
#include <string.h>
#include <dslink/stream.h>
#include <dslink/utils.h>

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
            Stream *stream = dslink_malloc(sizeof(Stream));
            if (!stream) {
                return 1;
            }
            stream->type = INVOCATION_STREAM;
            stream->path = dslink_strdup(node->path);

            ref_t *stream_ref = dslink_ref(stream, dslink_free);

            json_t *jsonRid = json_object_get(req, "rid");
            json_t *params = json_object_get(req, "params");
            node->on_invocation(link, node, jsonRid, params, stream_ref);

            if (stream->unused != 1) {
                dslink_decref(stream_ref);
            } else {
                ref_t *rid = dslink_ref(dslink_malloc(sizeof(uint32_t)), dslink_free);
                {
                    uint32_t r = (uint32_t) json_integer_value(jsonRid);
                    *((uint32_t *) rid->data) = r;
                }

                if (dslink_map_set(link->responder->open_streams,
                                   rid,
                                   stream_ref) != 0) {
                    dslink_free(rid);
                    dslink_free(stream_ref);
                    dslink_free(stream);
                    return 1;
                }
            }
        }
    } else if (strcmp(method, "close") == 0) {
        json_t *rid = json_object_get(req, "rid");
        uint32_t ridi = (uint32_t) json_integer_value(rid);
        ref_t *stream_ref = dslink_map_remove_get(link->responder->open_streams, &ridi);
        if (stream_ref) {
            Stream *stream = stream_ref->data;

            DSNode *node = NULL;

            if (stream->path) {
                node = dslink_node_get_path(link->responder->super_root, stream->path);
            }

            if (stream->on_close != NULL) {
                stream->on_close(link, node, stream);
            }

            if (stream->type == LIST_STREAM) {
                dslink_map_remove(link->responder->list_subs, (void *) stream->path);
            }

            dslink_decref(stream_ref);
        }
    } else {
        log_warn("Unrecognized method: %s\n", method);
    }
    return 0;
}
