#include <dslink/utils.h>
#include "broker/data/data.h"
#include "broker/net/ws.h"
#include "broker/broker.h"
#include "broker/msg/msg_set.h"

int broker_msg_handle_set(RemoteDSLink *link, json_t *req) {
    const char *path = json_string_value(json_object_get(req, "path"));
    json_t *rid = json_object_get(req, "rid");
    if (!(path && rid)) {
        return 1;
    }

    char *out = NULL;
    BrokerNode *node = broker_node_get(link->broker->root, path, &out);
    if (node && node->type == DOWNSTREAM_NODE) {
        uint32_t reqRid = (uint32_t) json_integer_value(rid);
        if (out == NULL) {
            out = "/";
        }

        DownstreamNode *dsn = (DownstreamNode *) node;
        json_t *top = json_object();
        json_t *reqs = json_array();
        json_object_set_new_nocheck(top, "requests", reqs);
        json_object_set_new_nocheck(req, "rid", json_integer(reqRid));
        json_object_set_new_nocheck(req, "path", json_string(out));
        json_array_append(reqs, req);

        broker_ws_send_obj(dsn->link, top);
        json_decref(top);
    } else if (node) {
        json_t *value = json_object_get(req, "value");
        broker_data_node_update(node, value, 0);
    } else if (dslink_str_starts_with(path, "/data")) {
        json_t *value = json_object_get(req, "value");
        broker_create_dynamic_data_node(link->broker, link->broker->root, path, value, 1);
    }

    return 0;
}
