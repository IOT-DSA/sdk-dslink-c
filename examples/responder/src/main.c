#define LOG_TAG "main"

#include <dslink/log.h>
#include <dslink/requester.h>
#include "replicator.h"
#include "rng.h"
#include "invoke.h"

void on_req_new_val(struct DSLink *link, json_t *resp) {
    (void) link;
    printf("Got response %s\n", json_dumps(resp, JSON_INDENT(2)));
    dslink_requester_close(link, json_integer_value(json_object_get(resp, "rid")));
}

void on_req_close(struct DSLink *link, json_t *resp) {
    (void) link;
    (void) resp;
    printf("Request closed.\n");
}

void init(DSLink *link) {
    DSNode *superRoot = link->responder->super_root;

    responder_init_replicator(link, superRoot);
    responder_init_rng(link, superRoot);
    responder_init_invoke(link, superRoot);

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

void requester_ready(DSLink *link) {
    ref_t *ref = dslink_requester_list(link, "/downstream", on_req_new_val);
    RequestHolder *req = ref->data;
    req->close_cb = on_req_close;
}

int main(int argc, char **argv) {
    DSLinkCallbacks cbs = {
        init,
        connected,
        disconnected,
        requester_ready
    };

    return dslink_init(argc, argv, "C-Resp", 1, 1, &cbs);
}
