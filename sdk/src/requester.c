#include "dslink/dslink.h"
#include "dslink/requester.h"
#include "dslink/ws.h"

json_t* dslink_requester_create_request(DSLink *link, const char *method) {
    (void) link;
    json_t *json = json_object();
    json_object_set_new(json, "method", json_string(method));
    return json;
}

ref_t* dslink_requester_send_request_with_rid(DSLink *link, json_t *req, request_handler_cb cb, uint32_t rid) {
    RequestHolder *holder = dslink_malloc(sizeof(RequestHolder));
    holder->rid = rid;
    holder->cb = cb;
    ref_t *ridf = dslink_int_ref(rid);
    ref_t *cbref = dslink_ref(holder, dslink_free);
    dslink_incref(cbref);
    dslink_map_set(link->requester->request_handlers, ridf, cbref);
    json_object_set(req, "rid", json_integer(rid));

    json_t *top = json_object();
    json_t *requests = json_array();
    json_array_append_new(requests, req);
    json_object_set_new(top, "requests", requests);

    dslink_ws_send_obj(link->_ws, top);
    return cbref;
}

ref_t* dslink_requester_send_request(DSLink *link, json_t *req, request_handler_cb cb) {
    uint32_t rid = ++*link->requester->rid;
    return dslink_requester_send_request_with_rid(link, req, cb, rid);
}

ref_t* dslink_requester_list(DSLink* link, const char* path, request_handler_cb cb) {
    json_t *json = dslink_requester_create_request(link, "list");

    json_object_set_new(json, "path", json_string(path));

    return dslink_requester_send_request(link, json, cb);
}

static
void dslink_requester_ignore_response(DSLink *link, json_t *resp) {
    (void) link;
    (void) resp;
}

ref_t* dslink_requester_subscribe(DSLink* link, const char* path, value_sub_cb cb) {
    uint32_t sid = ++(*link->requester->sid);

    json_t *json = dslink_requester_create_request(link, "subscribe");
    json_t *paths = json_array();
    json_t *obj = json_object();
    json_object_set(obj, "path", json_string(path));
    json_object_set(obj, "sid", json_integer(sid));
    json_array_append_new(paths, obj);
    json_object_set(json, "paths", paths);

    json_object_set_new(json, "paths", paths);

    ref_t *ref = dslink_requester_send_request(link, json, dslink_requester_ignore_response);
    RequestHolder *holder = ref->data;
    holder->sid = sid;

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

int dslink_requester_close(DSLink *link, uint32_t rid) {
    json_t *json = dslink_requester_create_request(link, "close");
    json_object_set(json, "rid", json_integer(rid));

    json_t *top = json_object();
    json_t *requests = json_array();
    json_array_append_new(requests, json);
    json_object_set_new(top, "requests", requests);

    dslink_ws_send_obj(link->_ws, top);
    return 0;
}
