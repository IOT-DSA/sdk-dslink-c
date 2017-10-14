#include <inttypes.h>
#include <string.h>

#define LOG_TAG "server"
#include <dslink/log.h>
#include <dslink/err.h>
#include <dslink/socket_private.h>
#include <dslink/mem/mem.h>
#include <uv-common.h>
#include <broker/upstream/upstream_handshake.h>

#include "broker/utils.h"
#include "broker/broker.h"

static
void broker_server_free_client(uv_poll_t *poll) {
    Client *client = poll->data;
    dslink_socket_free(&client->sock);
    dslink_free(client);
    uv_close((uv_handle_t *) poll, broker_free_handle);
}

static
void stop_server_handler(uv_signal_t* handle, int signum) {
    const char *sig;
    if (signum == SIGINT) {
        sig = "SIGINT";
    } else if (signum == SIGTERM) {
        sig = "SIGTERM";
    } else {
        // Ignore unknown signal
        return;
    }
    log_warn("Received %s, gracefully terminating broker...\n", sig);

    Broker* broker = handle->loop->data;
    broker_stop(broker);
    uv_stop(handle->loop);
}

static
void sigpipe_handler(uv_signal_t* handle, int signum) {
    (void)handle;
    (void)signum;
    log_warn("Received SIGPIPE, ignored...\n");
}

///////////////////////////////////////////////////////////////////////////////////////////////////


static
void broker_server_client_ready(uv_poll_t *poll,
                                int status,
                                int events) {
    (void) status;

    //TODO: (ali) delete later
    log_debug("Poll triggered\n");

    Client *client = poll->data;
    if(client) {
        Server *server = client->server;

        if (server &&
            (events & UV_READABLE)) {
            server->data_ready(client, poll->loop->data);
            if (client->sock->fd == -1) {
                broker_server_free_client(poll);
                client = NULL;
                log_debug("Client cleared\n");
            }
        } else if (status == -EBADF && events ==0) {
            //broker_server_client_fail(poll);
            // The callback closed the connection
            RemoteDSLink *link = client->sock_data;
            if (link) {
                broker_close_link(link);
            } else {
                broker_server_free_client(poll);
            }
            client = NULL;
        }

        if (client && (events & UV_WRITABLE)) {
            RemoteDSLink *link = client->sock_data;
            if (link && link->ws) {
                if(!wslay_event_want_write(link->ws)) {
                    log_debug("Stopping WRITE poll\n");
                    uv_poll_start(poll, UV_READABLE, broker_server_client_ready);
                } else {
                    log_debug("Enabling READ/WRITE poll on client\n");
                    uv_poll_start(poll, UV_READABLE | UV_WRITABLE, broker_server_client_ready);
#ifdef BROKER_WS_SEND_THREAD_MODE
                    uv_sem_wait(&link->broker->ws_queue_sem);
                    link->broker->currLink = link;
                    uv_sem_post(&link->broker->ws_send_sem);
#else
                    int stat = wslay_event_send(link->ws);
                    if(stat != 0) {
                        broker_close_link(link);
                        client = NULL;
                    }
#endif
                }
            }
        }
    }
}


///////////////////////////////////////////////////////////////////////////////////////////////////

static
void broker_server_new_client(uv_poll_t *poll,
                              int status, int events) {

    (void) status;
    (void) events;

    Server *server = poll->data;
    Socket *client_sock;

    if(dslink_socket_accept(server->sock, &client_sock) != 0)
    {
        return;
    }

    Client *client = dslink_calloc(1, sizeof(Client));
    if (!client) {
        dslink_socket_close(&client_sock);
        return;
    }

    client->is_local = dslink_check_socket_local(client_sock);
    client->server = server;
    client->sock = client_sock;

    uv_poll_t *clientPoll = dslink_malloc(sizeof(uv_poll_t));
    if (!clientPoll) {
        goto fail_poll_setup;
    }

    uv_loop_t *loop = poll->loop;
    if (uv_poll_init(loop, clientPoll,
                     client->sock->fd) != 0) {
        dslink_free(clientPoll);
        goto fail_poll_setup;
    }

    clientPoll->data = client;
    client->poll = clientPoll;
    client->poll_cb = broker_server_client_ready;
    uv_poll_start(clientPoll, UV_READABLE, client->poll_cb);

    log_debug("Accepted a client connection\n");
    return;

    fail_poll_setup:
    {
        dslink_socket_free(&client->sock);
        dslink_free(client);
    }
    return;
}


///////////////////////////////////////////////////////////////////////////////////////////////////

int broker_start_server(json_t *config) {
    json_incref(config);

    //////////////////////////
    ////// HTTP
    //////////////////////////
    ServerSettings* http_settings  = get_server_settings_from_json(json_object_get(config, "http" ), 0);
    Server httpServer;
    httpServer.is_active = 0;

    uv_poll_t httpPoll;
    if(http_settings->enabled)
    {
        int ret = start_server_with_server_settings(
                http_settings, &httpServer, mainLoop, &httpPoll);

        if(httpServer.is_active)
        {
            log_info("HTTP server bound successful to %s:%d\n",
                     http_settings->host, http_settings->port);
        }
        else
        {
            log_fatal("HTTP server bound failed to %s:%d, with error %d\n",
                      http_settings->host, http_settings->port, ret);
        }
    }
    dslink_free(http_settings);

    //////////////////////////
    /////// HTTPS
    //////////////////////////
    ServerSettings* https_settings = get_server_settings_from_json(json_object_get(config, "https"), 1);
    Server httpsServer;
    httpsServer.is_active = 0;

    uv_poll_t httpsPoll;
    if(https_settings->enabled)
    {
        int ret = start_server_with_server_settings(
                https_settings, &httpsServer, mainLoop, &httpsPoll);

        if(httpsServer.is_active)
        {
            log_info("HTTPS server bound successful to %s:%d\n",
                     https_settings->host, https_settings->port);
        }
        else
        {
            log_fatal("HTTPS server bound failed to %s:%d, with error %d\n",
                      https_settings->host, https_settings->port, ret);
        }
    }
    dslink_free(https_settings);

    uv_signal_t sigInt;
    uv_signal_init(mainLoop, &sigInt);
    uv_signal_start(&sigInt, stop_server_handler, SIGINT);

    uv_signal_t sigTerm;
    uv_signal_init(mainLoop, &sigTerm);
    uv_signal_start(&sigTerm, stop_server_handler, SIGTERM);

    uv_signal_t sigPipe;
    uv_signal_init(mainLoop, &sigPipe);
    uv_signal_start(&sigPipe, sigpipe_handler, SIGPIPE);

    if (httpServer.is_active || httpsServer.is_active)
        uv_run(mainLoop, UV_RUN_DEFAULT);
    else
        log_warn("Both http and https is inactive for some reason. So exiting...")

    uv_signal_stop(&sigInt);
    uv_signal_stop(&sigTerm);

    // Deinit http
    if (httpServer.is_active)
        uv_poll_stop(&httpPoll);

    if (httpsServer.is_active)
        uv_poll_stop(&httpsPoll);

    uv_loop_close(mainLoop);
//#if defined(__unix__) || defined(__APPLE__)
//    if (mainLoop && mainLoop->watchers) {
//        uv__free(mainLoop->watchers);
//    }
//#endif

    json_decref(config);
    return 0;
}


///////////////////////////////////////////////////////////////////////////////////////////////////

ServerSettings* get_server_settings_from_json(json_t *main_object, int secure) {
    // First initialize empty
    ServerSettings *settings = malloc(sizeof(ServerSettings));
    settings->enabled = 0;
    settings->port = -1;
    settings->host = NULL;
    settings->is_secure = secure;
    settings->cert_file = NULL;
    settings->cert_key_file = NULL;

    if (!main_object)
        return settings;

    json_t *enabled_object = json_object_get(main_object, "enabled");
    if(!enabled_object)
        return settings;

    settings->enabled = json_boolean_value(enabled_object);
    if(!settings->enabled)
        return settings;

    json_t *host_object = json_object_get(main_object, "host");
    if(host_object)
        settings->host = json_string_value(host_object);

    json_t *port_object = json_object_get(main_object, "port");
    if(port_object)
        settings->port = json_integer_value(port_object);

    if(settings->is_secure)
    {
        json_t *jsonCertName = json_object_get(main_object, "certName");
        if(jsonCertName)
            settings->cert_file = json_string_value(jsonCertName);

        json_t *jsonCertKeyName = json_object_get(main_object, "certKeyName");
        if(jsonCertKeyName)
            settings->cert_key_file = json_string_value(jsonCertKeyName);
    }

    return settings;
}

int start_server_with_server_settings(ServerSettings *settings, Server *server,
                                      uv_loop_t *loop, uv_poll_t *poll) {

    server->is_active = 0;

    int ret = 0;

    if(!settings->host || settings->port == -1)
        return DSLINK_INVALID_ADDRESS_OR_PORT_ERR;

    server->sock = dslink_socket_init(settings->is_secure);
    server->data_ready = broker_on_data_callback;

    // Setup socket
    Socket *socket = server->sock;
    ret = dslink_socket_bind(socket, settings->host, settings->port);

    if(ret != 0) {
        log_fatal("Failed to bind to %s:%d, with error code %d\n", settings->host, settings->port, ret);
        return ret;
    }

    if(settings->is_secure)
    {
        if(!settings->cert_file || !settings->cert_key_file)
        {
            ret = DSLINK_SOCK_SSL_CERT_ERR;
            log_fatal("Not specified certification file\n");
            goto close_socket_and_exit;
        }

        ret = load_certificates(socket->ssl_ctx, settings->cert_file, settings->cert_key_file);

        if( ret != 1)
        {
            goto close_socket_and_exit;
        }

        log_debug("HTTPS server certs ok!\n");
    }

    server->is_active = 1;

    uv_poll_init(loop, poll, socket->fd);
    poll->data = server;
    uv_poll_start(poll, UV_READABLE, broker_server_new_client);

    return 1;

    close_socket_and_exit:
    dslink_socket_close(&socket);
    return ret;
}

char* concat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1)+strlen(s2)+1);//+1 for the zero-terminator
    //in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

int load_certificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile) {

    char* file_path = concat("certs/", CertFile);
    int ret =  SSL_CTX_use_certificate_file(ctx, file_path, SSL_FILETYPE_PEM);
    free(file_path);

    if(ret <= 0)
    {
        log_fatal("SSL cert file read error!\n");
        return DSLINK_SOCK_SSL_CERT_READ_ERR;
    }

    file_path = concat("certs/", KeyFile);
    ret = SSL_CTX_use_PrivateKey_file(ctx, file_path, SSL_FILETYPE_PEM);
    free(file_path);

    if(ret <= 0)
    {
        log_fatal("SSL key file read error!\n");
        return DSLINK_SOCK_SSL_CERT_READ_ERR;
    }

    // verify private key
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        log_fatal("SSL check private key error!\n");
        return DSLINK_SOCK_SSL_CERT_ERR;
    }

    return 1;

}
