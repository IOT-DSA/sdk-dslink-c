#include <broker/upstream/upstream_handshake.h>
#include <dslink/dslink.h>
#include <dslink/handshake.h>
#include <dslink/utils.h>
#include <string.h>
#include <dslink/socket_private.h>
#include <mbedtls/net.h>
#include <dslink/ws.h>

#define LOG_TAG "upstream"

#include <dslink/log.h>
#include <broker/net/ws_handler.h>
#include <broker/remote_dslink.h>
#include <broker/upstream/upstream_node.h>


void upstream_free_dslink(DSLink *link) {
    mbedtls_ecdh_free(&link->key);
    dslink_url_free(link->config.broker_url);
    dslink_free((char *) link->config.name);
    dslink_free(link);
}

static
void upstream_io_handler(uv_poll_t *poll, int status, int events) {
    (void) events;
    if (status < 0) {
        return;
    }
    UpstreamPoll *upstreamPoll = poll->data;
    int stat = wslay_event_recv(upstreamPoll->ws);
    if (stat == 0 && (upstreamPoll->ws->error == WSLAY_ERR_NO_MORE_MSG
                      || upstreamPoll->ws->error == 0)) {
        uv_stop(upstreamPoll->loop);
    }
}

static
int gen_mask_cb(wslay_event_context_ptr ctx,
                uint8_t *buf, size_t len,
                void *user_data) {
    (void) ctx;
    (void) user_data;
    while (len-- > 0) {
        *(buf + len) = (uint8_t) rand();
    }
    return 0;
}

static
void broker_handshake_handle_ws(UpstreamPoll *upstreamPoll) {
    static const struct wslay_event_callbacks callbacks = {
            broker_want_read_cb,  // wslay_event_recv_callback
            broker_want_write_cb, // wslay_event_send_callback
            gen_mask_cb,          // wslay_event_genmask_callback
            NULL,          // wslay_event_on_frame_recv_start_callback
            NULL,          // wslay_event_on_frame_recv_chunk_callback
            NULL,          // wslay_event_on_frame_recv_end_callback
            broker_on_ws_data     // wslay_event_on_msg_recv_callback
    };


    RemoteDSLink *link = dslink_calloc(1, sizeof(RemoteDSLink));
    broker_remote_dslink_init(link);
    link->isUpstream = 1;
    link->isRequester = 1;
    link->isRequester = 1;
    link->broker = upstreamPoll->loop->data;
    link->name = upstreamPoll->name;


    Client * client = dslink_calloc(1, sizeof(Client));
    link->client = client;
    client->sock = upstreamPoll->sock;
    client->poll = &upstreamPoll->wsPoll;
    client->sock_data = link;

    upstreamPoll->remoteDSLink = link;


    wslay_event_context_ptr ptr;
    if (wslay_event_context_client_init(&ptr, &callbacks, link) != 0) {
        return;
    }
    upstreamPoll->ws = ptr;
    link->ws = ptr;

    mbedtls_net_set_nonblock(&upstreamPoll->clientDslink->_socket->socket_fd);

    uv_poll_init(upstreamPoll->loop, &upstreamPoll->wsPoll, upstreamPoll->clientDslink->_socket->socket_fd.fd);
    upstreamPoll->wsPoll.data = upstreamPoll;
    uv_poll_start(&upstreamPoll->wsPoll, UV_READABLE, upstream_io_handler);

    init_upstream_node(upstreamPoll->loop->data, upstreamPoll);
}

static
void connect_conn_callback(uv_poll_t *handle, int status, int events) {
    (void) status;
    (void) events;
    UpstreamPoll *upstreamPoll = handle->data;
    char *resp = NULL;

    int respLen = 0;
    while (1) {
        char buf[1024];
        int read = dslink_socket_read(upstreamPoll->sock, buf, sizeof(buf) - 1);
        if (read <= 0) {
            break;
        }
        if (resp == NULL) {
            resp = dslink_malloc((size_t) read + 1);
            respLen = read;
            memcpy(resp, buf, (size_t) read);
            *(resp + respLen) = '\0';
        } else {
            char *tmp = realloc(resp, (size_t) respLen + read + 1);
            resp = tmp;
            memcpy(resp + respLen, buf, (size_t) read);
            respLen += read;
            *(resp + respLen) = '\0';
        }
    }

    json_t *handshake = NULL;
    dslink_parse_handshake_response(resp, &handshake);

    dslink_free(resp);
    uv_poll_stop(handle);
    dslink_socket_close_nofree(upstreamPoll->sock);
    dslink_socket_free(upstreamPoll->sock);
    upstreamPoll->sock = NULL;

    if (handshake) {
        const char *uri = json_string_value(json_object_get(handshake, "wsUri"));
        const char *tKey = json_string_value(json_object_get(handshake, "tempKey"));
        const char *salt = json_string_value(json_object_get(handshake, "salt"));

        if (!(uri && tKey && salt)) {
            log_warn("Handshake didn't return the necessary parameters to complete\n");
            goto exit;
        }

        if ((dslink_handshake_connect_ws(upstreamPoll->clientDslink->config.broker_url, &upstreamPoll->clientDslink->key, uri,
                                         tKey, salt, upstreamPoll->dsId, &upstreamPoll->sock)) != 0) {
            log_warn("Failed to connect to broker\n");
            goto exit;
        } else {
            log_info("Successfully connected to the broker\n");
        }

        upstreamPoll->clientDslink->_socket = upstreamPoll->sock;

        broker_handshake_handle_ws(upstreamPoll);

    }
    exit:
    json_decref(handshake);

}

void upstream_connect_conn(uv_loop_t *loop, const char *brokerUrl, const char *name) {

    DSLink *clientDslink = dslink_calloc(1, sizeof(DSLink));
    clientDslink->is_requester = 1;
    clientDslink->is_responder = 1;
    dslink_handle_key(clientDslink);

    clientDslink->config.name = dslink_strdup(name);
    clientDslink->config.broker_url = dslink_url_parse(brokerUrl);

    char *dsId;
    Socket *sock;

    char *conndata = dslink_handshake_generate_req(clientDslink, &dsId);

    if (dslink_socket_connect(&sock, clientDslink->config.broker_url->host,
                              clientDslink->config.broker_url->port,
                              clientDslink->config.broker_url->secure) != 0) {
        goto exit;
    }
    dslink_socket_write(sock, conndata, strlen(conndata));

    UpstreamPoll *upstreamPoll = dslink_calloc(1, sizeof(UpstreamPoll));

    uv_poll_init(loop, &upstreamPoll->connPoll, sock->socket_fd.fd);

    upstreamPoll->name = dslink_strdup(name);
    upstreamPoll->dsId = dslink_strdup(dsId);
    upstreamPoll->connPoll.data = upstreamPoll;
    upstreamPoll->loop = loop;
    upstreamPoll->clientDslink = clientDslink;
    upstreamPoll->sock = sock;

    uv_poll_start(&upstreamPoll->connPoll, UV_READABLE, connect_conn_callback);

    exit:
    dslink_free(dsId);
}
