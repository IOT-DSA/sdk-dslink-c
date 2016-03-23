#define LOG_TAG "main"

#include <dslink/log.h>
#include <dslink/requester.h>

void on_req_new_val(struct DSLink *link, json_t *resp) {
    (void) link;
    printf("Got response %s\n", json_dumps(resp, JSON_INDENT(2)));
    dslink_requester_close(link, (uint32_t) json_integer_value(json_object_get(resp, "rid")));
}

void on_val_sub(struct DSLink *link, uint32_t sid, json_t *val, json_t *ts) {
    (void) link;
    (void) ts;
    (void) sid;
    printf("Got value %f\n", json_real_value(val));
    dslink_requester_unsubscribe(link, sid);
}

void on_req_close(struct DSLink *link, json_t *resp) {
    (void) link;
    (void) resp;
    json_t *rid = json_object_get(resp, "rid");
    printf("Request %i closed.\n", (int) json_integer_value(rid));
}

void init(DSLink *link) {
    (void) link;
    log_info("Initialized!\n");
}

void connected(DSLink *link) {
    (void) link;
    log_info("Connected!\n");
}

void disconnected(DSLink *link) {
    (void) link;
    log_info("Disconnected!\n");
}

void configure_request(ref_t *ref) {
    RequestHolder *req = ref->data;
    req->close_cb = on_req_close;
}

void requester_ready(DSLink *link) {
    configure_request(dslink_requester_list(link, "/downstream", on_req_new_val));
    configure_request(dslink_requester_subscribe(link, "/downstream/System/CPU_Usage", on_val_sub));
}

int main(int argc, char **argv) {
    DSLinkCallbacks cbs = {
        init,
        connected,
        disconnected,
        requester_ready
    };

    return dslink_init(argc, argv, "C-Requester", 1, 0, &cbs);
}
