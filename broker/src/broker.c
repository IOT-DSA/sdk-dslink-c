#include <string.h>

#include <wslay_event.h>

#include "broker/handshake.h"
#include "broker/config.h"
#include "broker/data/data.h"
#include "broker/sys/sys.h"

#define LOG_TAG "broker"
#include <dslink/log.h>
#include <dslink/utils.h>

#include <dslink/storage/storage.h>

#include <broker/upstream/upstream_node.h>
#include <broker/utils.h>
#include <broker/net/ws.h>

#define CONN_RESP "HTTP/1.1 200 OK\r\n" \
                    "Connection: close\r\n" \
                    "Access-Control-Allow-Origin: *\r\n" \
                    "Content-Type:application/json; charset=utf-8\r\n" \
                    "Content-Length: %d\r\n" \
                    "\r\n%s\r\n"

#ifndef GIT_COMMIT_HASH
#define GIT_COMMIT_HASH "unknown"
#endif

uv_loop_t *mainLoop = NULL;

static
void handle_conn(Broker *broker, HttpRequest *req, Socket *sock) {
    json_error_t err;

    json_t *body;
    {
        const char *start = strchr(req->body, '{');
        const char *end = strrchr(req->body, '}');
        if (!(start && end)) {
            goto exit;
        }
        body = json_loadb(start, end - start + 1, 0, &err);
        if (!body) {
            broker_send_internal_error(sock);
            goto exit;
        }
    }

    const char *dsId = broker_http_param_get(&req->uri, "dsId");
    if (!dsId) {
        goto exit;
    }
    log_info("%s connecting \n", dsId);
    const char *token = broker_http_param_get(&req->uri, "token");
    json_t *resp = broker_handshake_handle_conn(broker, dsId, token, body);
    json_decref(body);
    if (!resp) {
        broker_send_internal_error(sock);
        goto exit;
    }

    char *data = json_dumps(resp, JSON_INDENT(2));
    json_decref(resp);
    if (!data) {
        broker_send_internal_error(sock);
        goto exit;
    }

    char buf[1024];
    int len = snprintf(buf, sizeof(buf) - 1,
                       CONN_RESP, (int) strlen(data), data);
    buf[len] = '\0';
    dslink_free(data);
    dslink_socket_write(sock, buf, (size_t) len);

exit:
    return;
}

static
int handle_ws(Broker *broker, HttpRequest *req, Client *client) {
    size_t len = 0;
    const char *key = broker_http_header_get(req->headers,
                                             "Sec-WebSocket-Key", &len);
    if (!key) {
        goto fail;
    }
    char accept[64];
    if (broker_ws_generate_accept_key(key, len, accept, sizeof(accept)) != 0) {
        goto fail;
    }

    const char *dsId = broker_http_param_get(&req->uri, "dsId");
    const char *auth = broker_http_param_get(&req->uri, "auth");
    if (!(dsId && auth)) {
        goto fail;
    }

    if (broker_handshake_handle_ws(broker, client, dsId,
                                   auth, accept) != 0) {
        goto fail;
    }

    return 0;
fail:
    broker_send_bad_request(client->sock);
    dslink_socket_close_nofree(client->sock);
    return 1;
}

void broker_on_data_callback(Client *client, void *data) {
    Broker *broker = data;
    RemoteDSLink *link = client->sock_data;
    if (link) {
        link->ws->read_enabled = 1;
        wslay_event_recv(link->ws);
        if (link->pendingClose) {
            broker_close_link(link);
        }
        return;
    }

    HttpRequest req;
    char buf[1024];
    {
        int read = dslink_socket_read(client->sock, buf, sizeof(buf) - 1);
        buf[read] = '\0';
        broker_http_parse_req(&req, buf);
    }

    if (strcmp(req.uri.resource, "/conn") == 0) {
        if (strcmp(req.method, "POST") != 0) {
            log_info("invalid method on /conn \n");
            broker_send_bad_request(client->sock);
            goto exit;
        }

        handle_conn(broker, &req, client->sock);
    } else if (strcmp(req.uri.resource, "/ws") == 0) {
        if (strcmp(req.method, "GET") != 0) {
            log_info("invalid method on /ws \n");
            broker_send_bad_request(client->sock);
            goto exit;
        }

        handle_ws(broker, &req, client);
        return;
    } else {
        broker_send_not_found_error(client->sock);
    }

exit:
    dslink_socket_close_nofree(client->sock);
}

void broker_close_link(RemoteDSLink *link) {
    if (!link) {
        return;
    }
    if (link->client) {
        dslink_socket_close_nofree(link->client->sock);
    }
    if (link->dsId) {
        log_info("DSLink `%s` has disconnected\n", (char *) link->dsId->data);
    } else {
        log_info("DSLink `%s` has disconnected\n", (char *) link->name);
    }

    ref_t *ref;
    if (link->isUpstream) {
        ref = dslink_map_get(link->broker->upstream->children, (void *) link->name);
    } else {
       ref = dslink_map_get(link->broker->downstream->children, (void *) link->name);
    }

    broker_remote_dslink_free(link);
    // it's possible that free link still rely on node->link to close related streams
    // so link need to be freed before disconnected from node
    if (ref) {
        DownstreamNode *node = ref->data;
        broker_dslink_disconnect(node);
    }

    dslink_free(link);
}

static
void broker_free(Broker *broker) {
    if (broker->storage) {
        dslink_storage_destroy(broker->storage);
    }

    broker_node_free(broker->root);
    dslink_map_free(&broker->client_connecting);
    dslink_map_free(&broker->remote_pending_sub);
    dslink_map_free(&broker->local_pending_sub);
    memset(broker, 0, sizeof(Broker));
}

static
int broker_init(Broker *broker, json_t *defaultPermission) {
    broker->root = broker_node_create("", "node");
    if (!broker->root) {
        goto fail;
    }
    broker->root->permissionList = permission_list_load(defaultPermission);

    broker->root->path = dslink_strdup("/");
    json_object_set_new(broker->root->meta, "$downstream",
                        json_string_nocheck("/downstream"));

    broker->sys = broker_node_create("sys", "static");
    if (!(broker->sys && broker_node_add(broker->root, broker->sys) == 0)) {
        broker_node_free(broker->sys);
        goto fail;
    }

    broker->upstream = broker_node_create("upstream", "static");
    if (!(broker->upstream && broker_node_add(broker->root, broker->upstream) == 0)) {
        broker_node_free(broker->upstream);
        goto fail;
    }

    broker->data = broker_node_create("data", "node");
    if (!(broker->data && broker_node_add(broker->root, broker->data) == 0
          && broker_load_data_nodes(broker) == 0
          && broker_data_node_populate(broker->data) == 0)) {
        broker_node_free(broker->data);
        goto fail;
    }

    broker->downstream = broker_node_create("downstream", "node");
    if (!(broker->downstream
          && broker_node_add(broker->root, broker->downstream) == 0)) {
        broker_node_free(broker->downstream);
        goto fail;
    }
    broker_load_downstream_nodes(broker);
    broker_load_qos_storage(broker);

    if (broker_sys_node_populate(broker->sys)) {
        goto fail;
    }




    BrokerNode *node = broker_node_create("defs", "static");
    if (!(node && json_object_set_new_nocheck(node->meta,
                                              "$hidden",
                                              json_true()) == 0
          && broker_node_add(broker->root, node) == 0)) {
        broker_node_free(node);
        goto fail;
    }

    if (dslink_map_init(&broker->client_connecting, dslink_map_str_cmp,
                        dslink_map_str_key_len_cal, dslink_map_hash_key) != 0) {
        goto fail;
    }

    if (dslink_map_init(&broker->remote_pending_sub, dslink_map_str_cmp,
                        dslink_map_str_key_len_cal, dslink_map_hash_key) != 0) {
        goto fail;
    }

    if (dslink_map_init(&broker->local_pending_sub, dslink_map_str_cmp,
                        dslink_map_str_key_len_cal, dslink_map_hash_key) != 0) {
        goto fail;
    }

    return 0;
fail:
    broker_free(broker);
    return 1;
}

void broker_stop(Broker* broker) {
    dslink_map_foreach(broker->downstream->children) {
        DownstreamNode *node = entry->value->data;

        // Ensure the dsId is freed
        node->dsId->count = 1;
        dslink_decref(node->dsId);
        node->dsId = NULL;

        if (node->link) {
            RemoteDSLink *link = node->link;
            dslink_socket_close(link->client->sock);
            uv_close((uv_handle_t *) link->client->poll,
                     broker_free_handle);
            dslink_free(link->client);
            link->client = NULL;
            broker_remote_dslink_free(link);
        }
    }
}

int broker_start() {
    log_info("Git Commit: %s\n", GIT_COMMIT_HASH);

    int ret = 0;
    json_t *config = broker_config_get();
    if (!config) {
        ret = 1;
        return ret;
    }

    Broker broker;
    memset(&broker, 0, sizeof(Broker));

    mainLoop = dslink_calloc(1, sizeof(uv_loop_t));
    uv_loop_init(mainLoop);
    mainLoop->data = &broker;

    json_t *defaultPermission = json_object_get(config, "defaultPermission");

    broker_config_load(config);

    broker.storage = dslink_storage_init(config);
    broker.storage->loop = mainLoop;

    if (broker_init(&broker, defaultPermission) != 0) {
        ret = 1;
        goto exit;
    }

    ret = broker_start_server(config);
exit:
    json_decref(config);
    broker_free(&broker);
    dslink_free(mainLoop);
    return ret;
}
