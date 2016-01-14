#ifndef SDK_DSLINK_C_HTTP_H
#define SDK_DSLINK_C_HTTP_H

#ifdef __cplusplus
extern "C" {
#endif

#define DSLINK_URI_PARAMS_SIZE 8

typedef struct HttpUri {
    const char *resource;
    const char *paramKeys[DSLINK_URI_PARAMS_SIZE];
    const char *paramValues[DSLINK_URI_PARAMS_SIZE];
} HttpUri;

typedef struct HttpRequest {
    const char *method;
    const char *body;
    HttpUri uri;
} HttpRequest;

void dslink_http_parse_req(HttpRequest *request, char *data);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_HTTP_H
