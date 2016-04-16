#define LOG_TAG "main"

#include <dslink/log.h>
#include <dslink/requester.h>

void on_req_close(struct DSLink *link, ref_t *req_ref, json_t *resp) {
    (void) link;
    (void) resp;
    (void) req_ref;
    json_t *rid = json_object_get(resp, "rid");
    printf("Request %i closed.\n", (int) json_integer_value(rid));
}

void configure_request(ref_t *ref) {
    RequestHolder *req = ref->data;
    req->close_cb = on_req_close;
}

void on_invoke_updates(struct DSLink *link, ref_t *req_ref, json_t *resp) {
    (void) link;
    (void) req_ref;
    char *data = json_dumps(resp, JSON_INDENT(2));
    printf("Got invoke %s\n", data);
    dslink_free(data);
}

ref_t *streamInvokeRef = NULL;
void on_timer_fire(uv_timer_t *timer) {
    static int count = 0;

    DSLink *link = timer->data;

    if (count == 3) {
        printf("We are done.\n");
        uv_timer_stop(timer);
        uv_close((uv_handle_t *) timer, (uv_close_cb) dslink_free);
        dslink_close(link);
        return;
    }


    // set value
    json_t *value = json_real(rand());
    configure_request(dslink_requester_set(
        link,
        "/data/c-sdk/requester/testNumber",
        value
    ));
    json_decref(value);

    // stream invoke
    json_t *params = json_object();
    json_object_set_new(params, "Path", json_string("/data/test_c_sdk"));
    json_object_set_new(params, "Value", json_integer(count));
    RequestHolder *holder = streamInvokeRef->data;
    dslink_requester_invoke_update_params(link, holder->rid, params);
    json_decref(params);

    count++;
}
void start_stream_invoke(DSLink *link) {
    json_t *params = json_object();
    json_object_set_new(params, "Path", json_string("/data/test_c_sdk"));
    json_object_set_new(params, "Value", json_integer(-1));
    streamInvokeRef = dslink_requester_invoke(
            link,
            "/data/publish",
            params,
            on_invoke_updates
    );
    json_decref(params);
    configure_request(streamInvokeRef);
}

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
            char *data = json_dumps(val, JSON_INDENT(0));
            printf("%s = %s\n", json_string_value(name), data);
            dslink_free(data);
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

void requester_ready(DSLink *link) {
    configure_request(dslink_requester_list(link, "/downstream", on_list_update));
    configure_request(dslink_requester_subscribe(
        link,
        "/downstream/System/CPU_Usage",
        on_value_update,
        0
    ));
    configure_request(dslink_requester_set(link, "/downstream/Weather/@test", json_integer(4)));

    start_stream_invoke(link);
    
    uv_timer_t *timer = malloc(sizeof(uv_timer_t));
    timer->data = link;
    uv_timer_init(&link->loop, timer);
    uv_timer_start(timer, on_timer_fire, 0, 2000);
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
