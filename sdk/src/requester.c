#include "dslink/dslink.h"
#include "dslink/requester.h"
#include "dslink/ws.h"

static
void dslink_requester_ignore_response(DSLink *link, ref_t *req, json_t *resp) {
    (void) link;
    (void) resp;
    (void) req;
}

json_t* dslink_requester_create_request(DSLink *link, const char *method) {
    (void) link;
    json_t *json = json_object();
    json_object_set_new(json, "method", json_string(method));
    return json;
}

uint32_t dslink_requester_incr_rid(Requester *requester) {
    if (*requester->rid >= INT32_MAX) {
        // Loop it around
        (*requester->rid) = 0;
    }
    return ++(*requester->rid);
}

uint32_t dslink_requester_incr_sid(Requester *requester) {
    if (*requester->sid >= INT32_MAX) {
        // Loop it around
        (*requester->sid) = 0;
    }
    return ++(*requester->sid);
}

static
void dslink_requester_holder_free(void *obj) {
    RequestHolder *holder = obj;
    if (holder->req) {
        dslink_free(holder->req);
    }

    dslink_free(holder);
}

ref_t* dslink_requester_send_request_with_rid(DSLink *link, json_t *req, request_handler_cb cb, uint32_t rid) {
    RequestHolder *holder = dslink_malloc(sizeof(RequestHolder));
    holder->rid = rid;
    holder->cb = cb;
    holder->close_cb = dslink_requester_ignore_response;
    holder->req = json_incref(req);

    ref_t *ridf = dslink_int_ref(rid);
    ref_t *cbref = dslink_ref(holder, dslink_requester_holder_free);
    dslink_incref(cbref);
    dslink_map_set(link->requester->request_handlers, ridf, cbref);
    json_object_set(req, "rid", json_integer(rid));

    json_t *top = json_object();
    json_t *requests = json_array();
    json_array_append_new(requests, req);
    json_object_set(top, "requests", requests);

    dslink_ws_send_obj(link->_ws, top);
    json_decref(top);
    return cbref;
}

ref_t* dslink_requester_send_request(DSLink *link, json_t *req, request_handler_cb cb) {
    uint32_t rid = dslink_requester_incr_rid(link->requester);
    return dslink_requester_send_request_with_rid(link, req, cb, rid);
}

ref_t* dslink_requester_list(DSLink* link, const char* path, request_handler_cb cb) {
    json_t *json = dslink_requester_create_request(link, "list");

    json_object_set_new(json, "path", json_string(path));

    return dslink_requester_send_request(link, json, cb);
}

ref_t* dslink_requester_subscribe(DSLink* link, const char* path, value_sub_cb cb, int qos) {
    uint32_t sid = dslink_requester_incr_sid(link->requester);

    json_t *json = dslink_requester_create_request(link, "subscribe");
    json_t *paths = json_array();
    json_t *obj = json_object();
    json_object_set(obj, "path", json_string(path));
    json_object_set(obj, "sid", json_integer(sid));
    json_object_set(obj, "qos", json_integer(qos));
    json_array_append_new(paths, obj);
    json_object_set(json, "paths", paths);

    json_object_set_new(json, "paths", paths);

    ref_t *ref = dslink_requester_send_request(link, json, dslink_requester_ignore_response);
    RequestHolder *holder = ref->data;
    holder->sid = sid;
    holder->req = json;

    SubscribeCallbackHolder *subhold = dslink_malloc(sizeof(SubscribeCallbackHolder));
    subhold->cb = cb;
    ref_t *cbref = dslink_ref(subhold, dslink_free);

    dslink_map_set(
        link->requester->value_handlers,
        dslink_int_ref(sid),
        cbref
    );

    return ref;
}

ref_t* dslink_requester_set(DSLink* link, const char* path, json_t *value) {
    json_t *json = dslink_requester_create_request(link, "set");
    json_object_set_new(json, "path", json_string(path));
    json_object_set_new(json, "value", value);

    return dslink_requester_send_request(link, json, dslink_requester_ignore_response);
}

ref_t* dslink_requester_remove(DSLink* link, const char* path) {
    json_t *json = dslink_requester_create_request(link, "remove");
    json_object_set_new(json, "path", json_string(path));

    return dslink_requester_send_request(link, json, dslink_requester_ignore_response);
}

ref_t* dslink_requester_unsubscribe(DSLink* link, uint32_t sid) {
    json_t *json = dslink_requester_create_request(link, "unsubscribe");
    json_t *sids = json_array();
    json_array_append_new(sids, json_integer(sid));
    json_object_set_new(json, "sids", sids);

    ref_t *ref = dslink_requester_send_request(link, json, dslink_requester_ignore_response);
    RequestHolder *holder = ref->data;
    holder->sid = sid;
    return ref;
}

ref_t* dslink_requester_invoke(DSLink *link, const char *path, json_t *params, request_handler_cb cb) {
    json_t *json = dslink_requester_create_request(link, "invoke");
    json_object_set_new(json, "path", json_string(path));
    json_object_set_new(json, "params", params);

    ref_t *ref = dslink_requester_send_request(link, json, cb);
    return ref;
}

int dslink_requester_close(DSLink *link, uint32_t rid) {
    json_t *json = dslink_requester_create_request(link, "close");
    json_object_set(json, "rid", json_integer(rid));

    json_t *top = json_object();
    json_t *requests = json_array();
    json_array_append_new(requests, json);
    json_object_set_new(top, "requests", requests);

    dslink_ws_send_obj(link->_ws, top);
    json_delete(top);
    return 0;
}
