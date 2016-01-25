#include <string.h>
#include <dslink/utils.h>
#include <dslink/socket.h>

#include "broker/net/http.h"

static
void broker_http_parse_uri(HttpUri *uri, char *data) {
    memset(uri->paramKeys, 0, sizeof(uri->paramKeys));
    memset(uri->paramValues, 0, sizeof(uri->paramValues));
    char *loc = strstr(data, "?");
    if (!loc) {
        uri->resource = data;
        return;
    }

    *loc = '\0';
    uri->resource = data;

    data = ++loc;
    size_t pos = 0;
    while ((loc = strstr(data, "&")) && pos < BROKER_URI_PARAMS_SIZE) {
        char *sep = strstr(data, "=");
        if (sep) {
            if (sep > loc) {
                // No value
                goto no_value;
            } else {
                // We found a value
                *sep = '\0';
                uri->paramKeys[pos] = data;
                data = ++sep;
                *loc = '\0';
                uri->paramValues[pos++] = data;
                data = ++loc;
            }
        } else {
            // No value
no_value:
            *loc = '\0';
            uri->paramKeys[pos++] = data;
            data = ++loc;
            continue;
        }
    }

    if (*data != '\0' && pos < BROKER_URI_PARAMS_SIZE) {
        char *sep = strstr(data, "=");
        uri->paramKeys[pos] = data;
        if (sep) {
            *sep = '\0';
            data = ++sep;
            uri->paramValues[pos] = data;
        }
    }
}

const char *broker_http_header_get(const char *headers,
                                   const char *name, size_t *len) {
    const char *loc = dslink_strcasestr(headers, name);
    if (!loc) {
        return NULL;
    }

    headers = loc + strlen(name);
    loc = strstr(headers, "\r\n");
    if (!loc) {
        return NULL;
    }

    if (*headers == ':') {
        headers++;
    }
    while (*headers == ' ') {
        headers++;
    }

    *len = loc - headers;
    return headers;
}

const char *broker_http_param_get(const HttpUri *uri, const char *name) {
    for (int i = 0; i < BROKER_URI_PARAMS_SIZE; ++i) {
        const char *key = uri->paramKeys[i];
        if (key && strcmp(key, name) == 0) {
            return uri->paramValues[i];
        }
    }
    return NULL;
}

int broker_http_parse_req(HttpRequest *req, char *data) {
    char *loc = strstr(data, " ");
    if (!loc) {
        return 1;
    }
    *loc = '\0';
    req->method = data;
    data = ++loc;

    loc = strstr(data, " ");
    if (!loc) {
        return 1;
    }
    *loc = '\0';
    broker_http_parse_uri(&req->uri, data);
    data = ++loc;

    loc = strstr(data, "\r\n");
    if (!loc) {
        return 1;
    }
    data = loc + 2;

    loc = strstr(data, "\r\n\r\n");
    if (!loc) {
        return 1;
    }
    *loc = '\0';
    req->headers = data;
    req->body = loc + 4;

    return 0;
}

void broker_send_bad_request(Socket *sock) {
    char data[] = "HTTP/1.1 400 Bad Request\r\n\r\n";
    dslink_socket_write(sock, data, sizeof(data));
}

void broker_send_internal_error(Socket *sock) {
    char data[] = "HTTP/1.1 500 Internal Server Error\r\n\r\n";
    dslink_socket_write(sock, data, sizeof(data));
}

void broker_send_not_found_error(Socket *sock) {
    char data[] = "HTTP/1.1 404 Not Found\r\n\r\n";
    dslink_socket_write(sock, data, sizeof(data));
}
