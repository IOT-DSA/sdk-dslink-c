#include <inttypes.h>
#include <string.h>

#define LOG_TAG "server"
#include <dslink/log.h>
#include <dslink/socket_private.h>
#include <dslink/mem/mem.h>
#include <uv-common.h>
#include <broker/upstream/upstream_handshake.h>

#include "broker/utils.h"
#include "broker/broker.h"

#include "mbedtls/error.h"
#include "mbedtls/debug.h"

#define DEBUG_LEVEL 0

static void mbed_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);
    ((void) ctx);
    log_info( "%s:%04d: %s", file, line, str );
}

struct Server {
    mbedtls_net_context srv;
    DataReadyCallback data_ready;
};

struct SslServer {
    mbedtls_net_context srv;
    DataReadyCallback data_ready;
    mbedtls_x509_crt srvcert;
    mbedtls_pk_context pkey;
};

static
void broker_server_free_client(uv_poll_t *poll) {
    Client *client = poll->data;
    dslink_socket_free(client->sock);
    dslink_free(client);
    uv_close((uv_handle_t *) poll, broker_free_handle);
}

static
void broker_server_client_ready(uv_poll_t *poll,
                                int status,
                                int events) {
    (void) status;
    Client *client = poll->data;
    if(client) {
        Server *server = client->server;

        if (server &&
            (events & UV_READABLE)) {
            server->data_ready(client, poll->loop->data);
            if (client->sock->socket_ctx.fd == -1) {
                broker_server_free_client(poll);
                client = NULL;
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
                    int stat = wslay_event_send(link->ws);
                    if(stat != 0) {
                        broker_close_link(link);
                        client = NULL;
                    }
                }
            }
        }
    }
}

static
void broker_ssl_server_client_ready(uv_poll_t *poll,
                                int status,
                                int events) {
    (void) status;
    Client *client = poll->data;
    SslServer *server = (SslServer*)client->server;
    SslSocket* sslSocket = (SslSocket*)client->sock;

    if (client &&
        server &&
        sslSocket &&
        (events & UV_READABLE)) {
        server->data_ready(client, poll->loop->data);
        if (sslSocket->socket_ctx.fd == -1) {
            broker_server_free_client(poll);
            client = NULL;
        }
    } else if (status == -EBADF && events ==0 && client) {
        // broker_server_client_fail(poll);
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
                log_debug("Stopping WRITE poll on client\n");
                uv_poll_start(poll, UV_READABLE, broker_ssl_server_client_ready);
            } else {
                log_debug("Enabling READ/WRITE poll on client\n");
                uv_poll_start(poll, UV_READABLE | UV_WRITABLE, broker_ssl_server_client_ready);
                int stat = wslay_event_send(link->ws);
                if(stat != 0) {
                    broker_close_link(link);
                    client = NULL;
                }
            }
        }
    }
}

static
void broker_server_new_client(uv_poll_t *poll,
                              int status, int events) {
    (void) status;
    (void) events;

    Server *server = poll->data;
    Client *client = dslink_calloc(1, sizeof(Client));
    if (!client) {
        goto fail;
    }

    client->server = server;
    client->sock = dslink_socket_init(0);
    if (!client->sock) {
        dslink_free(client);
        goto fail;
    }

    if (mbedtls_net_accept(&server->srv, &client->sock->socket_ctx,
                           NULL, 0, NULL) != 0) {
        log_warn("Failed to accept a client connection\n");
        goto fail_poll_setup;
    }

    uv_poll_t *clientPoll = dslink_malloc(sizeof(uv_poll_t));
    if (!clientPoll) {
        goto fail_poll_setup;
    }

    uv_loop_t *loop = poll->loop;
    if (uv_poll_init(loop, clientPoll,
                     client->sock->socket_ctx.fd) != 0) {
        dslink_free(clientPoll);
        goto fail_poll_setup;
    }

    clientPoll->data = client;
    client->poll = clientPoll;
    client->poll_cb = broker_server_client_ready;
    uv_poll_start(clientPoll, UV_READABLE | UV_WRITABLE, client->poll_cb);

    log_debug("Accepted a client connection\n");
    return;
fail:
    {
        mbedtls_net_context tmp;
        mbedtls_net_init(&tmp);
        mbedtls_net_accept(&server->srv, &tmp, NULL, 0, NULL);
        mbedtls_net_free(&tmp);
    }
    return;
fail_poll_setup:
    dslink_socket_free(client->sock);
    dslink_free(client);
}

static
void broker_ssl_server_new_client(uv_poll_t *poll,
                              int status, int events) {
    (void) status;
    (void) events;

    int ret;
    const char *pers = "ssl_server";

    SslServer *server = poll->data;
    Client *client = dslink_calloc(1, sizeof(Client));
    if (!client) {
        goto fail;
    }

    client->server = (Server*)server;
    client->sock = dslink_socket_init(1);
    if (!client->sock) {
        dslink_free(client);
        goto fail;
    }

    SslSocket *sslSocket = (SslSocket*)client->sock;

    //Seed the RNG
    if( ( ret = mbedtls_ctr_drbg_seed( &sslSocket->drbg, mbedtls_entropy_func, &sslSocket->entropy,
                                       (const unsigned char *) pers,
                                       strlen( pers ) ) ) != 0 )
    {
        log_fatal( " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto fail_poll_setup;
    }

    if( ( ret = mbedtls_ssl_config_defaults( &sslSocket->conf,
                                             MBEDTLS_SSL_IS_SERVER,
                                             MBEDTLS_SSL_TRANSPORT_STREAM,
                                             MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
        log_fatal( " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret );
        goto fail_poll_setup;
    }

    mbedtls_ssl_conf_cert_profile(&sslSocket->conf, &mbedtls_x509_crt_profile_next);

    static int preset_suiteb_hashes[] = {
        MBEDTLS_MD_SHA512,
        MBEDTLS_MD_SHA384,
        MBEDTLS_MD_SHA256,
        MBEDTLS_MD_NONE
    };
    mbedtls_ssl_conf_sig_hashes(&sslSocket->conf, preset_suiteb_hashes);

    static int ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_RSA_WITH_AES_128_GCM_SHA256,
        MBEDTLS_TLS_RSA_WITH_AES_256_GCM_SHA384,
        0
    };

    mbedtls_ssl_conf_ciphersuites(&sslSocket->conf, ciphersuites);

    mbedtls_ssl_conf_min_version(&sslSocket->conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

    mbedtls_ssl_conf_rng( &sslSocket->conf, mbedtls_ctr_drbg_random, &sslSocket->drbg );
    mbedtls_ssl_conf_dbg( &sslSocket->conf, mbed_debug, stdout );

    mbedtls_ssl_conf_ca_chain( &sslSocket->conf, server->srvcert.next, NULL );
    if( ( ret = mbedtls_ssl_conf_own_cert( &sslSocket->conf, &server->srvcert, &server->pkey ) ) != 0 )
    {
        log_fatal( " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret );
        goto fail_poll_setup;
    }

    if( ( ret = mbedtls_ssl_setup( &sslSocket->ssl, &sslSocket->conf ) ) != 0 )
    {
        log_fatal( " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
        goto fail_poll_setup;
    }

    mbedtls_net_free( &sslSocket->socket_ctx );
    mbedtls_ssl_session_reset( &sslSocket->ssl );

    if (mbedtls_net_accept(&server->srv, &sslSocket->socket_ctx,
                           NULL, 0, NULL) != 0) {
        log_warn("Failed to accept a client connection\n");
        goto fail_poll_setup;
    }

    mbedtls_ssl_set_bio( &sslSocket->ssl, &sslSocket->socket_ctx, mbedtls_net_send, mbedtls_net_recv, NULL );

    //Handshake
    log_debug( "  . Performing the SSL/TLS handshake...\n" );
    while( ( ret = mbedtls_ssl_handshake( &sslSocket->ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            log_fatal( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
            goto fail_poll_setup;
        }
    }


    uv_poll_t *clientPoll = dslink_malloc(sizeof(uv_poll_t));
    if (!clientPoll) {
        goto fail_poll_setup;
    }

    uv_loop_t *loop = poll->loop;
    if (uv_poll_init(loop, clientPoll,
                     client->sock->socket_ctx.fd) != 0) {
        dslink_free(clientPoll);
        goto fail_poll_setup;
    }

    clientPoll->data = client;
    client->poll = clientPoll;
    client->poll_cb = broker_ssl_server_client_ready;
    uv_poll_start(clientPoll, UV_READABLE, client->poll_cb);

    log_debug("Accepted a client connection\n");
    return;
    fail:
    {
        mbedtls_net_context tmp;
        mbedtls_net_init(&tmp);
        mbedtls_net_accept(&server->srv, &tmp, NULL, 0, NULL);
        mbedtls_net_free(&tmp);
    }
    return;
    fail_poll_setup:
    dslink_socket_free(client->sock);
    dslink_free(client);
}

static
int start_http_server(Server *server, const char *host,
                       const char *port, uv_loop_t *loop,
                       uv_poll_t *poll) {
    if (mbedtls_net_bind(&server->srv, host, port, MBEDTLS_NET_PROTO_TCP) != 0) {
        log_fatal("Failed to bind to %s:%s\n", host, port);
        return 0;
    } else {
        log_info("HTTP server bound to %s:%s\n", host, port);
    }

    uv_poll_init(loop, poll, server->srv.fd);
    poll->data = server;
    uv_poll_start(poll, UV_READABLE, broker_server_new_client);
    return 1;
}

static
int start_https_server(SslServer *server, const char *host,
                      const char *port, const char *certFile, const char *certKeyFile,
                       uv_loop_t *loop, uv_poll_t *poll) {

    int ret;

    mbedtls_debug_set_threshold( DEBUG_LEVEL );
    //Load the certificates and private RSA key
    ret = mbedtls_x509_crt_parse_file( &server->srvcert, certFile );
    if( ret != 0 )
    {
        log_fatal( " failed\n  !  mbedtls_x509_crt_parse returned %d\n\n", ret );
        return 0;
    }

    ret =  mbedtls_pk_parse_keyfile( &server->pkey,certKeyFile,NULL );
    if( ret != 0 )
    {
        log_fatal( " failed\n  !  mbedtls_pk_parse_key returned %d\n\n", ret );
        return 0;
    }

    //Setup the listening TCP socket
    if (mbedtls_net_bind(&server->srv, host, port, MBEDTLS_NET_PROTO_TCP) != 0) {
        log_fatal("Failed to bind to %s:%s\n", host, port);
        return 0;
    } else {
        log_info("HTTPS server bound to %s:%s\n", host, port);
    }


    uv_poll_init(loop, poll, server->srv.fd);
    poll->data = server;
    uv_poll_start(poll, UV_READABLE, broker_ssl_server_new_client);
    return 1;
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

int broker_start_server(json_t *config) {
    json_incref(config);

    int httpEnabled = 0, httpsEnabled = 0;
    const char *httpHost = NULL;
    char httpPort[8];
    memset(httpPort, 0, sizeof(httpPort));
    {
        json_t *http = json_object_get(config, "http");
        if (http) {
            json_t *enabled = json_object_get(http, "enabled");
//            if (!(enabled && json_boolean_value(enabled))) {
//                json_decref(config);
//                return 0;
//            }
            if(enabled && json_boolean_value(enabled)) {
                httpEnabled = 1;
                httpHost = json_string_value(json_object_get(http, "host"));

                json_t *jsonPort = json_object_get(http, "port");
                if (jsonPort) {
                    json_int_t p = json_integer_value(jsonPort);
                    int len = snprintf(httpPort, sizeof(httpPort) - 1,
                                       "%" JSON_INTEGER_FORMAT, p);
                    httpPort[len] = '\0';
                }
            }
        }
    }

    int httpActive = 0;
    Server httpServer;
    uv_poll_t httpPoll;
    if (httpEnabled && httpHost && httpPort[0] != '\0') {
        mbedtls_net_init(&httpServer.srv);
        httpServer.data_ready = broker_on_data_callback;

        httpActive = start_http_server(&httpServer, httpHost, httpPort,
                                       mainLoop, &httpPoll);
    }

    const char *httpsHost = NULL;
    char httpsCertFile[200] = "certs/";
    char httpsCertKeyFile[200] = "certs/";
    char httpsPort[8];
    memset(httpsPort, 0, sizeof(httpsPort));
    {
        json_t *https = json_object_get(config, "https");
        if (https) {
            json_t *enabled = json_object_get(https, "enabled");
//            if (!(enabled && json_boolean_value(enabled))) {
//                json_decref(config);
//                return 0;
//            }
            if (enabled && json_boolean_value(enabled)) {
                httpsEnabled = 1;
                httpsHost = json_string_value(json_object_get(https, "host"));

                json_t *jsonPort = json_object_get(https, "port");
                if (jsonPort) {
                    json_int_t p = json_integer_value(jsonPort);
                    int len = snprintf(httpsPort, sizeof(httpsPort) - 1,
                                       "%" JSON_INTEGER_FORMAT, p);
                    httpsPort[len] = '\0';
                }

                strcat(httpsCertFile, json_string_value(json_object_get(https, "certName")));
                strcat(httpsCertKeyFile, json_string_value(json_object_get(https, "certKeyName")));
            }

        }
    }

    int httpsActive = 0;
    SslServer httpsServer;
    uv_poll_t httpsPoll;
    if (httpsEnabled && httpsHost && httpsPort[0] != '\0') {
        mbedtls_net_init(&httpsServer.srv);
        mbedtls_x509_crt_init( &httpsServer.srvcert );
        mbedtls_pk_init( &httpsServer.pkey );
        httpsServer.data_ready = broker_https_on_data_callback;

        httpsActive = start_https_server(&httpsServer, httpsHost, httpsPort, httpsCertFile, httpsCertKeyFile,
                                       mainLoop, &httpsPoll);
    } else
        httpsEnabled = 0;


    uv_signal_t sigInt;
    uv_signal_init(mainLoop, &sigInt);
    uv_signal_start(&sigInt, stop_server_handler, SIGINT);

    uv_signal_t sigTerm;
    uv_signal_init(mainLoop, &sigTerm);
    uv_signal_start(&sigTerm, stop_server_handler, SIGTERM);

//    upstream_connect_conn(&loop, "http://10.0.1.158:8080/conn", "dartbroker", "cbroker");

    if (httpActive || httpsActive) {
        uv_run(mainLoop, UV_RUN_DEFAULT);
    }

    uv_signal_stop(&sigInt);
    uv_signal_stop(&sigTerm);


    if (httpActive) {
        uv_poll_stop(&httpPoll);
    }

    if(httpsEnabled) {
        mbedtls_x509_crt_free( &httpsServer.srvcert );
        mbedtls_pk_free( &httpsServer.pkey );
    }
    if (httpsActive) {
        uv_poll_stop(&httpsPoll);
    }

    uv_loop_close(mainLoop);
#if defined(__unix__) || defined(__APPLE__)
    if (mainLoop && mainLoop->watchers) {
        uv__free(mainLoop->watchers);
    }
#endif

    json_decref(config);
    return 0;
}
