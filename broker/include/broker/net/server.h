#ifndef BROKER_NET_SERVER_H
#define BROKER_NET_SERVER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <uv.h>
#include <jansson.h>
#include <dslink/socket.h>
#include <openssl/ssl.h>

#include "broker/net/http.h"

struct Client;

typedef void (*DataReadyCallback)(struct Client *client, void *data);
typedef void (*ClientErrorCallback)(void *socketData);

typedef struct Server {
    Socket *sock;
    DataReadyCallback data_ready;
    int is_active;
} Server;

typedef struct Client {
    Server *server;
    Socket *sock;
    void *sock_data;

    uv_poll_t *poll;
    uv_poll_cb poll_cb;
}Client;


int broker_start_server(json_t *config);


/////////////////////////////////////////////////////////////////////////////
typedef struct ServerSettings{
    int enabled;
    int port;
    const char* host;
    int is_secure;
    const char* cert_file;
    const char* cert_key_file;
}ServerSettings;

ServerSettings* get_server_settings_from_json(json_t *main_object, int secure);
int start_server_with_server_settings(ServerSettings *settings, Server *server,
                                      uv_loop_t *loop, uv_poll_t *poll);
int load_certificates(SSL_CTX* ctx, const char* CertFile, const char* KeyFile);
/////////////////////////////////////////////////////////////////////////////


#ifdef __cplusplus
}
#endif

#endif // BROKER_NET_SERVER_H
