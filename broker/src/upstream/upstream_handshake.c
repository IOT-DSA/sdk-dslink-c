#include <broker/upstream/upstream_handshake.h>
#include <dslink/dslink.h>
#include <dslink/handshake.h>
#include <dslink/utils.h>
#include <dslink/socket_private.h>
#include <dslink/ws.h>

#define LOG_TAG "upstream"

#include <dslink/log.h>
#include <broker/net/ws_handler.h>
#include <broker/remote_dslink.h>
#include <broker/upstream/upstream_node.h>
#include <broker/handshake.h>
#include <broker/utils.h>
#include <string.h>
#include <mbedtls/net.h>

static
void upstream_free_dslink(DSLink *link) {
    if (!link) {
        return;
    }
    mbedtls_ecdh_free(&link->key);
    dslink_url_free(link->config.broker_url);
    dslink_free((char *) link->config.name);
    dslink_free(link);
}

void upstream_clear_poll(UpstreamPoll *upstreamPoll) {
    if (upstreamPoll->status == UPSTREAM_CONN || upstreamPoll->status == UPSTREAM_CONN_CHECK) {
        if (upstreamPoll->connPoll) {
            uv_poll_stop(upstreamPoll->connPoll);
            uv_close((uv_handle_t *)upstreamPoll->connPoll, broker_free_handle);
        }
        if (upstreamPoll->connCheckTimer) {
            uv_timer_stop(upstreamPoll->connCheckTimer);
            uv_close((uv_handle_t *)upstreamPoll->connCheckTimer, broker_free_handle);
            upstreamPoll->connCheckTimer = NULL;
        }
        dslink_socket_close_nofree(upstreamPoll->sock);
        dslink_socket_free(upstreamPoll->sock);
        upstreamPoll->sock = NULL;
    } else if (upstreamPoll->status == UPSTREAM_WS) {
        uv_poll_stop(upstreamPoll->wsPoll);
        uv_close((uv_handle_t *)upstreamPoll->wsPoll, broker_free_handle);
        upstreamPoll->remoteDSLink->client->poll = NULL;
    }
    if (upstreamPoll->reconnectTimer) {
        uv_timer_stop(upstreamPoll->reconnectTimer);
        uv_close((uv_handle_t *)upstreamPoll->reconnectTimer, broker_free_handle);
        upstreamPoll->reconnectTimer = NULL;
    }
    if (upstreamPoll->conCheckAddrList) {
        freeaddrinfo( upstreamPoll->conCheckAddrList );
    }
    broker_close_link(upstreamPoll->remoteDSLink);
    upstream_free_dslink(upstreamPoll->clientDslink);
    upstreamPoll->clientDslink = NULL;
    upstreamPoll->remoteDSLink = NULL;
    upstreamPoll->sock = NULL;
    upstreamPoll->ws = NULL;
    upstreamPoll->status = UPSTREAM_NONE;
}

void upstrem_handle_reconnect(uv_timer_t* handle) {
    UpstreamPoll *upstreamPoll = handle->data;
    upstream_connect_conn(upstreamPoll);
}

void upstream_reconnect(UpstreamPoll *upstreamPoll) {
    upstream_clear_poll(upstreamPoll);
    if (upstreamPoll->reconnectInterval < 60) {
        upstreamPoll->reconnectInterval++;
    }
    log_info("reconnect in %d seconds\n", upstreamPoll->reconnectInterval);

    upstreamPoll->reconnectTimer = dslink_calloc(1, sizeof(uv_timer_t));
    upstreamPoll->reconnectTimer->data = upstreamPoll;
    uv_timer_init(mainLoop, upstreamPoll->reconnectTimer);
    uv_timer_start(upstreamPoll->reconnectTimer, upstrem_handle_reconnect, upstreamPoll->reconnectInterval*1000, 0);

}

/// This function reconnects the given upstream poll if an error occured
/// @param stat Return value of the wslay_event_recv or wslay_event_send functions
/// @param upstreamPoll Pointer to an upstream poll that will reconnected in case of an error
static
void reconnect_if_error_occured(int stat, UpstreamPoll* upstreamPoll) {
    if(!upstreamPoll) {
        return;
    }

    if(stat != 0 || (upstreamPoll->remoteDSLink->pendingClose == 1)) {
        upstream_reconnect(upstreamPoll);
    }
}

static
void upstream_io_handler(uv_poll_t *poll, int status, int events) {
    (void) events;
    if (status < 0) {
        return;
    }
    UpstreamPoll *upstreamPoll = poll->data;
    if(!upstreamPoll || !upstreamPoll->ws) {
        return;
    }

    if (events & UV_READABLE) {
        int stat = wslay_event_recv(upstreamPoll->ws);
        reconnect_if_error_occured(stat, upstreamPoll);
    }

    if (events & UV_WRITABLE) {
        if(!wslay_event_want_write(upstreamPoll->ws)) {
            log_debug("Stopping WRITE poll on upstream node\n");
            uv_poll_start(poll, UV_READABLE, upstream_io_handler);
        } else {
            log_debug("Enabling READ/WRITE poll on upstream node\n");
            uv_poll_start(poll, UV_READABLE | UV_WRITABLE, upstream_io_handler);
            int stat = wslay_event_send(upstreamPoll->ws);
            reconnect_if_error_occured(stat, upstreamPoll);
        }
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
void upstream_handshake_handle_ws(UpstreamPoll *upstreamPoll) {
    static const struct wslay_event_callbacks callbacks = {
            broker_want_read_cb,  // wslay_event_recv_callback
            broker_want_write_cb, // wslay_event_send_callback
            gen_mask_cb,          // wslay_event_genmask_callback
            NULL,          // wslay_event_on_frame_recv_start_callback
            NULL,          // wslay_event_on_frame_recv_chunk_callback
            NULL,          // wslay_event_on_frame_recv_end_callback
            broker_on_ws_data     // wslay_event_on_msg_recv_callback
    };

    RemoteDSLink *link = upstreamPoll->remoteDSLink;
    if(!link) {
        return;
    }

    Client * client = dslink_calloc(1, sizeof(Client));
    link->client = client;
    client->sock = upstreamPoll->sock;
    upstreamPoll->wsPoll = dslink_calloc(1, sizeof(uv_poll_t));
    client->poll = upstreamPoll->wsPoll;
    client->sock_data = link;

    upstreamPoll->remoteDSLink = link;


    wslay_event_context_ptr ptr;
    if (wslay_event_context_client_init(&ptr, &callbacks, link) != 0) {
        upstreamPoll->status = UPSTREAM_NONE;
        return;
    }
    upstreamPoll->ws = ptr;
    link->ws = ptr;

    mbedtls_net_set_nonblock(&upstreamPoll->clientDslink->_socket->socket_ctx);

    uv_poll_init(mainLoop, upstreamPoll->wsPoll, upstreamPoll->clientDslink->_socket->socket_ctx.fd);
    upstreamPoll->wsPoll->data = upstreamPoll;

    client->poll_cb = upstream_io_handler;
    uv_poll_start(upstreamPoll->wsPoll, UV_READABLE, upstream_io_handler);

    init_upstream_node(mainLoop->data, upstreamPoll);
}

static
void connect_conn_callback(uv_poll_t *handle, int status, int events) {
    (void) status;
    (void) events;
    UpstreamPoll *upstreamPoll = handle->data;

    if(!upstreamPoll) {
        return;
    }

    uv_poll_stop(handle);
    uv_close((uv_handle_t*)handle, broker_free_handle);
    upstreamPoll->connPoll = NULL;

    char *resp = NULL;

    int respLen = 0;
    while (1) {
        char buf[1024];
        int read = dslink_socket_read(upstreamPoll->sock, buf, sizeof(buf) - 1);
        if(read == DSLINK_SOCK_WOULD_BLOCK) {
            continue;
        }
        if(read == 0) {
            break;
        }
        if (read != DSLINK_SOCK_WOULD_BLOCK && read <= 0) {
            if(errno != EAGAIN) {
                dslink_free(resp);
                log_err("Error while reading from socket %d\n", errno);
                upstream_reconnect(upstreamPoll);
                return;
            }

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
                                         tKey, salt, upstreamPoll->dsId, NULL, &upstreamPoll->sock)) != 0) {
            upstream_reconnect(upstreamPoll);
            goto exit;
        } else {
            log_info("Successfully connected to the upstream broker '%s'\n", upstreamPoll->name);
        }

        upstreamPoll->clientDslink->_socket = upstreamPoll->sock;

        upstream_handshake_handle_ws(upstreamPoll);
        upstreamPoll->status = UPSTREAM_WS;
        upstreamPoll->reconnectInterval = 0;
    } else {
        upstreamPoll->status = UPSTREAM_NONE;
        upstream_reconnect(upstreamPoll);
    }
    exit:
    json_decref(handshake);

}

/// This function disables the given timer and calls the provided callback.
/// @param timer Pointer to the timer
/// @param callback The callback that is called when the timer is closed
void disable_timer(uv_timer_t* timer, uv_close_cb callback) {
    if(!timer) {
        return;
    }

    uv_timer_stop(timer);
    uv_close((uv_handle_t *)timer, callback);
}

void upstream_check_conn (uv_timer_t* handle) {
    UpstreamPoll *upstreamPoll = handle->data;
    if(!upstreamPoll) {
        return;
    }

    // If an error occurs upstream_reconnect will create the timer again.
    disable_timer(upstreamPoll->connCheckTimer, broker_free_handle);
    upstreamPoll->connCheckTimer = NULL;

    if (connectConnCheck(upstreamPoll) != 0) {
        upstream_reconnect(upstreamPoll);
        return;
    }

    upstreamPoll->status = UPSTREAM_CONN;
    char *dsId;
    char *conndata = dslink_handshake_generate_req(upstreamPoll->clientDslink, &dsId);

    if(DSLINK_SOCK_WRITE_ERR == dslink_socket_write(upstreamPoll->sock, conndata, strlen(conndata))) {
        upstream_reconnect(upstreamPoll);
        return;
    }

    upstreamPoll->connPoll = dslink_calloc(1, sizeof(uv_poll_t));
    uv_poll_init(mainLoop, upstreamPoll->connPoll, upstreamPoll->sock->socket_ctx.fd);

    upstreamPoll->dsId = dslink_strdup(dsId);
    upstreamPoll->connPoll->data = upstreamPoll;
    uv_poll_start(upstreamPoll->connPoll, UV_READABLE, connect_conn_callback);
    dslink_free(dsId);
}


void upstream_connect_conn(UpstreamPoll *upstreamPoll) {
    RemoteDSLink *link = dslink_malloc(sizeof(RemoteDSLink));
    bzero(link, sizeof(RemoteDSLink));
    broker_remote_dslink_init(link);
    permission_groups_load(&link->permission_groups, "", upstreamPoll->group);
    link->isUpstream = 1;
    link->isRequester = 1;
    link->isResponder = 1;
    link->node = upstreamPoll->node;
    link->broker = mainLoop->data;
    link->name = dslink_strdup(upstreamPoll->name);
    upstreamPoll->remoteDSLink = link;

    DSLink *clientDslink = dslink_malloc(sizeof(DSLink));
    bzero(clientDslink, sizeof(DSLink));
    clientDslink->is_requester = 1;
    clientDslink->is_responder = 1;
    dslink_handle_key(clientDslink);

    clientDslink->config.name = dslink_strdup(upstreamPoll->idPrefix);
    clientDslink->config.broker_url = dslink_url_parse(upstreamPoll->brokerUrl);

    upstreamPoll->clientDslink = clientDslink;

    log_debug("Trying to connect to %s\n", clientDslink->config.broker_url->host);
    if (dslink_socket_connect_async(upstreamPoll, clientDslink->config.broker_url->host,
                              clientDslink->config.broker_url->port,
                              clientDslink->config.broker_url->secure) != 0) {
        upstream_reconnect(upstreamPoll);
        return;
    }
    upstreamPoll->status = UPSTREAM_CONN_CHECK;

    upstreamPoll->connCheckTimer = dslink_malloc(sizeof(uv_timer_t));
    upstreamPoll->connCheckTimer->data = upstreamPoll;
    uv_timer_init(mainLoop, upstreamPoll->connCheckTimer);
    uv_timer_start(upstreamPoll->connCheckTimer, upstream_check_conn, 500, 0);
}


void upstream_create_poll(const char *brokerUrl, const char *name, const char *idPrefix, const char *group) {
    Broker *broker = mainLoop->data;

    DownstreamNode *node = create_upstream_node(broker, name);
    if (node ->upstreamPoll) {
        return;
    }

    UpstreamPoll *upstreamPoll = dslink_calloc(1, sizeof(UpstreamPoll));
    bzero(upstreamPoll, sizeof(UpstreamPoll));
    upstreamPoll->brokerUrl = dslink_strdup(brokerUrl);
    upstreamPoll->name = dslink_strdup(name);
    upstreamPoll->idPrefix = dslink_strdup(idPrefix);
    upstreamPoll->group = dslink_strdup(group);
    upstreamPoll->node = node;
    upstreamPoll->reconnectInterval = 0;

    node->upstreamPoll = upstreamPoll;

    upstream_connect_conn(upstreamPoll);
}
