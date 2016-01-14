#include <string.h>

#include "broker/http.h"

static
void dslink_http_parse_uri(HttpUri *uri, char *data) {
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
    while ((loc = strstr(data, "&")) && pos < DSLINK_URI_PARAMS_SIZE) {
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

    if (*data != '\0' && pos < DSLINK_URI_PARAMS_SIZE) {
        char *sep = strstr(data, "=");
        if (sep) {
            *sep = '\0';
            uri->paramKeys[pos] = data;
            data = ++sep;
            uri->paramValues[pos] = data;
        } else {
            uri->paramKeys[pos] = data;
        }
    }
}

void dslink_http_parse_req(HttpRequest *req, char *data) {
    char *loc = strstr(data, " ");
    if (!loc) {
        goto cleanup;
    }
    *loc = '\0';
    req->method = data;
    data = ++loc;

    loc = strstr(data, " ");
    if (!loc) {
        goto cleanup;
    }
    *loc = '\0';
    dslink_http_parse_uri(&req->uri, data);
    data = ++loc;

    loc = strstr(data, "\r\n\r\n");
    if (!loc) {
        goto cleanup;
    }
    loc += 4;
    req->body = loc;

    return;
cleanup:
    req->method = NULL;
    req->body = NULL;
    memset(&req->uri, 0, sizeof(HttpUri));
}
