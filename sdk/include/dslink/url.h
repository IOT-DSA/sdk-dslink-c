#ifndef SDK_DSLINK_C_URL_H
#define SDK_DSLINK_C_URL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef struct Url {
    uint_fast8_t secure;
    unsigned short port;
    char *scheme;
    char *host;
    char *uri;
} Url;

Url *dslink_url_parse(const char *address);

void dslink_url_free(Url *url);

void dslink_url_handle_scheme(const char *scheme,
                              unsigned short *port,
                              uint_fast8_t *secure);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_URL_H
