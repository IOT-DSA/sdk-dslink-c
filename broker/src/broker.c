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
#include <dslink/socket_private.h>
#include "uv-common.h"

#define CONN_RESP   "HTTP/1.1 200 OK\r\n" \
                    "Connection: close\r\n" \
                    "Access-Control-Allow-Origin: *\r\n" \
                    "Content-Type:application/json; charset=utf-8\r\n" \
                    "Content-Length: %d\r\n\r\n" \
                    "%s\r\n"

#ifndef IOT_DSA_C_SDK_GIT_COMMIT_HASH
#define IOT_DSA_C_SDK_GIT_COMMIT_HASH "unknown"
#endif

uv_loop_t *mainLoop = NULL;

static
void handle_conn(Broker *broker, HttpRequest *req, Socket *sock) {
    json_error_t err;
    char *dsId = NULL;
    json_t *body;
    {
        const char *start = strchr(req->body, '{');
        const char *end = strrchr(req->body, '}');
        if (!(start && end)) {
            log_warn("While handling connection body looks like empty (it has to have json), so ignoring the request...")
            broker_send_bad_request(sock);
            goto exit;
        }

        body = json_loadb(start, end - start + 1, 0, &err);
        if (!body) {
            broker_send_internal_error(sock);
            goto exit;
        }
    }

    dsId = dslink_str_unescape(broker_http_param_get(&req->uri, "dsId"));
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
                       CONN_RESP, (int) strlen(data) + 2, data); // +2 for /r/n
    buf[len] = '\0';
    dslink_free(data);
    dslink_socket_write(sock, buf, (size_t) len);

exit:
    if (dsId) {
        dslink_free(dsId);
    }
    return;
}

static
int handle_ws(Broker *broker, HttpRequest *req, Client *client) {
    int ret = 0;
    size_t len = 0;
    char *dsId = NULL;
    char *perm_group = NULL;
    const char *key = broker_http_header_get(req->headers,
                                             "Sec-WebSocket-Key", &len);
    if (!key) {
        ret = 1;
        goto exit;
    }
    char accept[64];
    if (broker_ws_generate_accept_key(key, len, accept, sizeof(accept)) != 0) {
        ret = 1;
        goto exit;
    }

    dsId = dslink_str_unescape(broker_http_param_get(&req->uri, "dsId"));
    const char *auth = broker_http_param_get(&req->uri, "auth");
    if (!(dsId && auth)) {
        if(client->is_local) {
            perm_group = dslink_str_unescape(broker_http_param_get(&req->uri, "group"));
            const char *session = broker_http_param_get(&req->uri, "session");
            const char *format = broker_http_param_get(&req->uri, "format");
            if(broker_local_handle_ws(broker, client, accept, perm_group, session, format) != 0) {
                log_debug("Broker local handle_ws failed\n");
                ret = 1;
                goto exit;
            }
        } else {
            ret = 1;
            goto exit;
        }
    } else if (broker_handshake_handle_ws(broker, client, dsId,
                                   auth, accept) != 0) {
        ret = 1;
        goto exit;
    }
exit:
    if (perm_group)
        dslink_free(perm_group);
    if (dsId)
        dslink_free(dsId);
    //if failed
    if(ret) {
        broker_send_bad_request(client->sock);
        dslink_socket_close_nofree(&client->sock);
    }
    return ret;
}

// Function to read from socket and process http
// returns 1 on success
// returns 0 if not finalized to socket empty
// returns -1 on error
int http_socket_read(Client *client, HttpRequest *req)
{
    if (client->sock->fd == -1) return -1;

    char temp_buffer[2048];
    temp_buffer[0] = (char)0;
    temp_buffer[1] = (char)0;
    temp_buffer[2] = (char)0;
    temp_buffer[3] = (char)0;

    int read = dslink_socket_read(client->sock, temp_buffer, sizeof(temp_buffer)-1);
    if(read <= 0) return -1;
    if(read == 0) return 0;

    if(client->http_buffer_so_far != 0)
    {
        // It should not be fresh http request
        // Check if it is freshing start
        if(dslink_str_starts_with(temp_buffer, "POST")==1)
            client->http_buffer_so_far = 0;
        else if(dslink_str_starts_with(temp_buffer, "GET")==1)
            client->http_buffer_so_far = 0;
    }

    // Add to the buffer
    char* buf = client->http_buffer;
    memcpy(buf+client->http_buffer_so_far, temp_buffer, read);
    client->http_buffer_so_far += read;
    buf[client->http_buffer_so_far] = (char)0;

    //Backup buffer
    memcpy(temp_buffer, buf, client->http_buffer_so_far + 1);

    // Parse HTTP
    int parse_error = broker_http_parse_req(req, buf);

    if(parse_error != 1) return -1;
    // Process Body
    int body_size = strlen(req->body);

    const char *result = NULL;
    size_t len = 0;

    result = broker_http_header_get(req->headers, "transfer-encoding", &len);
    if(result && dslink_str_starts_with(result, "chunked") == 1)
    {
        // chunked must end with "0\r\n\r\n" so it has at least char in body
        if(body_size < 5) goto not_finished;

        // means not finalized if not ends with 0\r\n\r\n
        const char* ptr_to_end = req->body + body_size - 5;
        if(dslink_str_starts_with(ptr_to_end, "0\r\n\r\n") != 1) goto not_finished;

        // It is finalized so! we should filter the markers
        const char* progress_so_far = (req->body - req->method) + &temp_buffer[0];
        const char* end_ptr = progress_so_far + strlen(progress_so_far);

        char* curr_ptr = (char*)req->body;

        // Structure:
        // HEXADECIMAL\r\nDATA\r\n
        // Implemented algorithm in https://en.wikipedia.org/wiki/Chunked_transfer_encoding
        while(true)
        {
            const char* hex_end_loc = strstr(progress_so_far, "\r\n");
            if(hex_end_loc > end_ptr) goto decode_error;

            char* hex_end = NULL;
            int num_bytes_in_data = (int)strtol(progress_so_far, &hex_end, 16);

            // Check if it is last chunk has zero byte
            if(num_bytes_in_data == 0) break;

            // Jumping from HEX\r\n to DATA\r\n
            progress_so_far = hex_end_loc + 2;

            // Check if it has error in byte count
            if(progress_so_far + num_bytes_in_data > end_ptr) goto decode_error;

            // Copying to our body
            memcpy(curr_ptr, progress_so_far, num_bytes_in_data);

            // Jumping from the data
            curr_ptr += num_bytes_in_data;
            progress_so_far += num_bytes_in_data + 2; // +2 for extra \r\n
        }

        // str close for the body
        curr_ptr[0] = (char) 0;

        return 1;
    }

    len = 0;
    result = broker_http_header_get(req->headers, "content-length", &len);
    if(result)
    {
        // Expect body len with transfer-encoding
        char num_buf[256];
        memcpy(num_buf, result, len);
        int num = atoi(num_buf);

        // If content len is not equal with body size?
        if(body_size < num) goto not_finished;
        if(body_size > num) goto decode_error;
    }

    return 1;

    not_finished:
    //Backup buffer
    memcpy(buf, temp_buffer, client->http_buffer_so_far + 1);
    return 0;

    decode_error:
    return -9;
}

void broker_on_data_callback(Client *client, void *data) {
    Broker *broker = data;
    RemoteDSLink *link = client->sock_data;

    if (link) {
        int ret;
        link->ws->read_enabled = 1;
        ret = wslay_event_recv(link->ws);
        if (ret || link->pendingClose) {
            log_info("Error in ws receive: %d\n", ret);
            // clear the poll now, so it won't get cleared twice
            link->client->poll = NULL;//because it is cleared in the broker_server_client_ready, after this callback
            broker_close_link(link);
        }
        return;
    }


    HttpRequest req;
    // Check http request
    int result = http_socket_read(client, &req);
    if( result ==  0) return;    // It is not finalized yet
    if( result == -1) goto exit; // Illegal response
    if( result == -9)
    {
        broker_send_bad_request(client->sock);
        goto exit;
    }

    // So it is 1 so we can continue
    // Reset the count for the next request
    client->http_buffer_so_far = 0;

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
    dslink_socket_close_nofree(&client->sock);
}

#ifdef BROKER_PING_THREAD
void broker_handle_ping_thread(void *arg) {

    Broker *broker = (Broker*)arg;
    while(1) {

        dslink_map_foreach(&broker->remote_connected) {
            RemoteDSLink *connLink = (RemoteDSLink *) entry->value->data;
            if (!dslink_generic_ping_handler(connLink)) {
                log_debug("Remote dslink problem while pinging!\n");
                broker_close_link(connLink);
            }
        }

        dslink_sleep(10000);
        if(broker->closing_ping_thread == 1)
            break;
    }

}
#endif

void _broker_close_link(RemoteDSLink *link) {

    if ((link)->client) {
        if ((link)->client->poll) {
            uv_close((uv_handle_t *) (link)->client->poll,
                     broker_free_handle);
        }
        dslink_socket_close_nofree(&(link)->client->sock);
    }
    if ((link)->dsId) {
        log_info("DSLink `%s` has disconnected  %s\n", (char *) (link)->dsId->data, (link)->name);
    } else {
        log_info("DSLink `%s` has disconnected\n", (char *) (link)->name);
    }

    ref_t *link_ref;
    if ((link)->dsId) {
        link_ref = dslink_map_remove_get(&(link)->broker->remote_connected,
                                         (link)->dsId->data);
        if (link_ref) {
            RemoteDSLink *rm_link = link_ref->data;
            dslink_free(link_ref);
            log_debug("DSLink %s has been removed from connected list, list size:%d\n", rm_link->name,(int)link->broker->remote_connected.size);
        }
    }

    ref_t *ref;
    if ((link)->isUpstream) {
        ref = dslink_map_get((link)->broker->upstream->children, (void *) (link)->name);
    } else {
        ref = dslink_map_get((link)->broker->downstream->children, (void *) (link)->name);
    }

    broker_remote_dslink_free((link));
    // it's possible that free link still rely on node->link to close related streams
    // so link need to be freed before disconnected from node
    if (ref) {
        DownstreamNode *node = ref->data;
        broker_dslink_disconnect(node);
    }

    dslink_decref((link)->dsId);
    if(link->lastReceiveTime) {
        dslink_free(link->lastReceiveTime);
    }
#ifdef BROKER_WS_SEND_THREAD_MODE
    if ((link)->broker && ((link)->broker->currLink == link)) {
        (link)->broker->currLink = NULL;
    }
#endif
#ifdef BROKER_CLOSE_LINK_SEM2
    uv_sem_destroy(&link->close_sem);
#endif
    dslink_free(link);
}

void broker_close_link(RemoteDSLink *link) {

    if (!link || link->pendingClose>1) {
        return;
    }
    link->pendingClose = 2;

#if defined(BROKER_CLOSE_LINK_SEM2)
    uv_sem_wait(&link->close_sem);
    _broker_close_link(link);
#else
    _broker_close_link(link);
#endif
}
static
void broker_free(Broker *broker) {
    if (broker->storage) {
        dslink_storage_destroy(broker->storage);
    }

    broker_node_free(broker->upstream); // in order to remove upstream before sys to avoid crash caused by throughput nodes
    broker_node_free(broker->root);
    dslink_map_free(&broker->client_connecting);
    dslink_map_free(&broker->remote_pending_sub);
    dslink_map_free(&broker->local_pending_sub);
    dslink_map_free(&broker->remote_connected);

    memset(broker, 0, sizeof(Broker));
}

static
int broker_init(Broker *broker, json_t *defaultPermission) {
    broker->root = broker_node_create("", "node");
    if (!broker->root) {
        goto fail;
    }
//    log_debug("defaultPermissions: %s\n",json_dumps(defaultPermission,JSON_PRESERVE_ORDER));
    broker->root->permissionList = permission_list_new_from_json(defaultPermission);

    broker->root->path = dslink_strdup("/");
    json_object_set_new_nocheck(broker->root->meta, "$downstream",
                        json_string_nocheck("/downstream"));

    json_object_set_new_nocheck(broker->root->meta, "$is", json_string_nocheck("dsa/broker"));

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

    if (dslink_map_init(&broker->remote_connected, dslink_map_str_cmp,
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

#ifdef BROKER_WS_SEND_THREAD_MODE
    broker->closing_send_thread = 0;
    uv_sem_init(&broker->ws_send_sem,0);
    uv_sem_init(&broker->ws_queue_sem,1);
    uv_thread_create(&broker->ws_send_thread_id, broker_send_ws_thread, broker);
    broker->currLink = NULL;
#endif

#ifdef BROKER_PING_THREAD
    broker->closing_ping_thread = 0;
    uv_thread_create(&broker->ping_thread_id, broker_handle_ping_thread, broker);
#endif

    return 0;
fail:
    broker_free(broker);
    return 1;
}

void broker_destroy_link(RemoteDSLink *link) {
    if (!link || link->pendingClose>1) {
        return;
    }
    Client *linkClient = link->client;
    broker_close_link(link);
    if(linkClient) {
        dslink_socket_free(&linkClient->sock);
        dslink_free(linkClient);
    }
}


void broker_stop(Broker* broker) {

#ifdef BROKER_WS_SEND_THREAD_MODE
    broker->closing_send_thread = 1;
    uv_sem_post(&broker->ws_send_sem);
#endif

    dslink_map_foreach(broker->downstream->children) {
        DownstreamNode *node = entry->value->data;

        // Ensure the dsId is freed
//        node->dsId->count = 1; //causes seg fault below

        // this is moved to broker_node_free
//        dslink_decref(node->dsId);
//        node->dsId = NULL;

        if (node->link) {
            RemoteDSLink *link = node->link;
            broker_destroy_link(link);

        }
    }

    //For the links that does not have downstream node
    dslink_map_foreach_nonext(&broker->remote_connected) {

        MapEntry *tmp = entry->next;

        RemoteDSLink* link = (RemoteDSLink*)entry->value->data;

        //do not close upstream remote dslinks, they will be closed later on while nodes being destroyed
        if(!link->isUpstream) {
            broker_destroy_link(link);
        }
        entry = tmp;
    }

#ifdef BROKER_WS_SEND_THREAD_MODE
    uv_thread_join(&broker->ws_send_thread_id);
    uv_sem_destroy(&broker->ws_send_sem);
    uv_sem_destroy(&broker->ws_queue_sem);
#endif

#ifdef BROKER_PING_THREAD
    broker->closing_ping_thread = 1;
    uv_thread_join(&broker->ping_thread_id);
#endif

    broker_free(broker);
}

//void broker_stop(Broker* broker) {
//
//#ifdef BROKER_WS_SEND_THREAD_MODE
//    broker->closing_send_thread = 1;
//    uv_sem_post(&broker->ws_send_sem);
//#endif
//
//    dslink_map_foreach(broker->downstream->children) {
//        DownstreamNode *node = entry->value->data;
//
//        // Ensure the dsId is freed
////        node->dsId->count = 1; //causes seg fault below
//        dslink_decref(node->dsId);
//        node->dsId = NULL;
//
//        if (node->link) {
//            RemoteDSLink *link = node->link;
//            if(link->pendingClose == 0)
//                link->pendingClose = 1;
//            dslink_socket_close(&link->client->sock);
//            uv_close((uv_handle_t *) link->client->poll,
//                     broker_free_handle);
//            dslink_free(link->client);
//            link->client = NULL;
//
//            ref_t *link_ref;
//            if(link->dsId) {
//                link_ref = dslink_map_remove_get(&link->broker->remote_connected,
//                                                 link->dsId->data);
//                if(link_ref) {
//                    RemoteDSLink *rm_link = link_ref->data;
//                    log_debug("DSLink %s has been removed from connected list\n", rm_link->name);
//                }
//            }
//            broker_remote_dslink_free(link);
//            dslink_decref(link->dsId);
//        }
//    }
//
//    //For the links that does not have downstream node
//    dslink_map_foreach_nonext(&broker->remote_connected) {
//
//        MapEntry *tmp = entry->next;
//
//        RemoteDSLink* link = (RemoteDSLink*)entry->value->data;
//
//        //do not close upstream remote dslinks, they are close later on
//        if(!link->isUpstream) {
//            dslink_socket_close(&link->client->sock);
//            uv_close((uv_handle_t *) link->client->poll,
//                     broker_free_handle);
//            dslink_free(link->client);
//            link->client = NULL;
//
//            ref_t *link_ref;
//            if (link->dsId) {
//                link_ref = dslink_map_remove_get(&link->broker->remote_connected,
//                                                 link->dsId->data);
//                if (link_ref) {
//                    RemoteDSLink *rm_link = link_ref->data;
//                    log_debug("DSLink %s has been removed from connected list\n", rm_link->name);
//                }
//            }
//            broker_remote_dslink_free(link);
//            dslink_decref(link->dsId);
//        }
//        entry = tmp;
//    }
//
//#ifdef BROKER_WS_SEND_THREAD_MODE
//    uv_thread_join(&broker->ws_send_thread_id);
//    uv_sem_destroy(&broker->ws_send_sem);
//    uv_sem_destroy(&broker->ws_queue_sem);
//#endif
//
//#ifdef BROKER_PING_THREAD
//    broker->closing_ping_thread = 1;
//    uv_thread_join(&broker->ping_thread_id);
//#endif
//
//    broker_free(broker);
//}

int broker_start() {
    log_info("IOT-DSA c-sdk git commit: %s\n", IOT_DSA_C_SDK_GIT_COMMIT_HASH);

    int ret = 0;
    json_t *config = broker_config_get();
    if (!config) {
        ret = 1;
        return ret;
    }

    dslink_crypto_fips_mode_set(1);

    Broker broker;
    memset(&broker, 0, sizeof(Broker));
    broker.pendingActionUpstreamPoll = NULL;

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
//    broker_free moved to the end of broker_stop in order to run it before mainloop stopped
//    because handles were not closed and freed properly after mainloop finished
//    broker_free(&broker);
#if defined(__unix__) || defined(__APPLE__)
    if (mainLoop && mainLoop->watchers) {
        uv__free(mainLoop->watchers);
    }
#endif
    dslink_free(mainLoop);
    return ret;
}
