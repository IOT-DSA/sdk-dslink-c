#include <jansson.h>
#include <string.h>

#include <dslink/utils.h>
#include "broker/config.h"
#include "broker/server.h"

void on_http_req_callback(HttpRequest *req, Socket *sock) {
    if (strcmp(req->uri.resource, "/conn") == 0) {
        // TODO
    } else if (strcmp(req->uri.resource, "/ws") == 0) {
        // TODO
    }

    char data[] = "HTTP/1.0 501 Not Implemented\r\n\r\n";
    dslink_socket_write(sock, data, sizeof(data));
    dslink_socket_close(sock);
}

int dslink_broker_init() {
    int ret = 0;
    json_t *config = dslink_broker_config_get();
    if (!config) {
        ret = 1;
        return ret;
    }

    ret = dslink_broker_start_server(config, on_http_req_callback);
    DSLINK_CHECKED_EXEC(json_delete, config);
    return ret;
}
