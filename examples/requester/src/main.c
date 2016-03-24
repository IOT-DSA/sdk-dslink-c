#define LOG_TAG "main"

#include <dslink/log.h>
#include <dslink/requester.h>

void on_list_update(struct DSLink *link, ref_t *req_ref, json_t *resp) {
    (void) link;
    RequestHolder *holder = req_ref->data;

    json_t *updates = json_object_get(resp, "updates");
    size_t index;
    json_t *value;

    const char* path = json_string_value(json_object_get(holder->req, "path"));

    printf("======= List %s =======\n", path);
    json_array_foreach(updates, index, value) {
        json_t *name = json_array_get(value, 0);
        json_t *val = json_array_get(value, 1);

        if (val->type == JSON_ARRAY || val->type == JSON_OBJECT) {
            printf("%s = %s\n", json_string_value(name), json_dumps(val, JSON_INDENT(0)));
        } else if (val->type == JSON_STRING) {
            printf("%s = %s\n", json_string_value(name), json_string_value(val));
        } else if (val->type == JSON_INTEGER) {
            printf("%s = %lli\n", json_string_value(name), json_integer_value(val));
        } else if (val->type == JSON_REAL) {
            printf("%s = %f\n", json_string_value(name), json_real_value(val));
        } else if (val->type == JSON_NULL) {
            printf("%s = NULL\n", json_string_value(name));
        } else if (val->type == JSON_TRUE) {
            printf("%s = true\n", json_string_value(name));
        } else if (val->type == JSON_FALSE) {
            printf("%s = false\n", json_string_value(name));
        } else {
            printf("%s = (Unknown Type)\n", json_string_value(name));
        }
    }

    dslink_requester_close(link, (uint32_t) json_integer_value(json_object_get(resp, "rid")));
}

void on_value_update(struct DSLink *link, uint32_t sid, json_t *val, json_t *ts) {
    (void) link;
    (void) ts;
    (void) sid;
    printf("Got value %f\n", json_real_value(val));
    dslink_requester_unsubscribe(link, sid);
}

void on_invoke_updates(struct DSLink *link, ref_t *req_ref, json_t *resp) {
    (void) link;
    (void) req_ref;
    printf("Got invoke %s\n", json_dumps(resp, JSON_INDENT(2)));
}

void on_req_close(struct DSLink *link, ref_t *req_ref, json_t *resp) {
    (void) link;
    (void) resp;
    (void) req_ref;
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
    configure_request(dslink_requester_list(link, "/downstream", on_list_update));
    configure_request(dslink_requester_subscribe(
        link,
        "/downstream/System/CPU_Usage",
        on_value_update,
        0
    ));
    configure_request(dslink_requester_set(link, "/downstream/Weather/@test", json_integer(4)));

    json_t *params = json_object();

    json_object_set_new(params, "command", json_string("ls"));

    configure_request(dslink_requester_invoke(
        link,
        "/downstream/System/Execute_Command",
        params,
        on_invoke_updates
    ));
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
