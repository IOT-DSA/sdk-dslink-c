#ifndef BROKER_NET_HTTP_H
#define BROKER_NET_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#define BROKER_URI_PARAMS_SIZE 8

typedef struct HttpUri {
    const char *resource;
    const char *paramKeys[BROKER_URI_PARAMS_SIZE];
    const char *paramValues[BROKER_URI_PARAMS_SIZE];
} HttpUri;

typedef struct HttpRequest {
    const char *method;
    const char *headers;
    const char *body;
    HttpUri uri;
} HttpRequest;

int broker_http_parse_req(HttpRequest *request, char *data);
const char *broker_http_header_get(const char *headers,
                                   const char *name, size_t *len);
const char *broker_http_param_get(const HttpUri *uri, const char *name);

void broker_send_bad_request(Socket *sock);
void broker_send_internal_error(Socket *sock);
void broker_send_not_found_error(Socket *sock);

#ifdef __cplusplus
}
#endif

#endif // BROKER_NET_HTTP_H
