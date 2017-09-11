#if defined(__linux__)
#include <stdint.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dslink/mem/mem.h"
#include "dslink/url.h"

#define URL_ADDRESS_SUBSTRING_COPY(var, len) \
    var = dslink_malloc(len + 1); \
    if (!var) goto exit; \
    for (uint_fast8_t i = 0; i < len; ++i) { \
        *(var + i) = *(address + i); \
    } \
    *(var + len) = '\0';

#define URL_ADDRESS_ASSIGN_URI_END(var) \
    var = dslink_malloc(2); \
    if (!var) goto exit; \
    *var = '/'; \
    *(var + 1) = '\0';

Url *dslink_url_parse(const char *address) {
    Url *url = dslink_calloc(1, sizeof(Url));
    uint_fast8_t state = 0;
    uint_fast8_t len = 0;
    for (char c = *address; c != '\0'; ++len) {
        if (c == ':' && state == 0) {
            // Parse the protocol
            --len; // Rewind a character
            URL_ADDRESS_SUBSTRING_COPY(url->scheme, len)
            do {
                c = *(address + (++len));
            } while (c == '/');
            dslink_url_handle_scheme_for_secure(url->scheme, &url->secure);
            if(c == '[') {
                state = 3;
            } else {
                state = 1;
            }
            address += len;
            len = 0;
        } else if ((c == ':' || c == '/') && state == 1) {
            // Parse the host
            --len; // Rewind a character
            URL_ADDRESS_SUBSTRING_COPY(url->host, len)
            if (c == ':') {
                state = 2;
                address += 1;
            } else {
                dslink_url_handle_scheme(url->scheme, &url->port, &url->secure);
                state = 4;
            }
            address += len;
            len = 0;
        } else if (c == '/' && state == 2) {
            // Parse the port
            --len; // Rewind a character
            char num[len + 1];
            for (uint_fast8_t i = 0; i < len; ++i) {
                *(num + i) = *(address + i);
            }
            *(num + len) = '\0';
            url->port = (unsigned short) strtol(num, NULL, 10);
            state = 4;
            address += len;
            len = 0;
        } else if ((c == ']') && state == 3) {
            // Parse the IPv6 host
            len -= 2; // Rewind
            address += 1;
            URL_ADDRESS_SUBSTRING_COPY(url->host, len)
            address += 1;
            c = *(address + len);
            if (c == ':') {
                state = 2;
                address += 1;
            } else {
                dslink_url_handle_scheme(url->scheme, &url->port, &url->secure);
                state = 4;
            }
            address += len;
            len = 0;
        }

        c = *(address + len);
    }

    if (state == 0) {
        goto exit;
    } else if (state == 1) {
        // Handle port and URI
        if (len <= 1) {
            goto exit;
        }
        dslink_url_handle_scheme(url->scheme, &url->port, &url->secure);
        URL_ADDRESS_ASSIGN_URI_END(url->uri)
        URL_ADDRESS_SUBSTRING_COPY(url->host, len)
    } else if (state == 2) {
        // Handle port
        URL_ADDRESS_ASSIGN_URI_END(url->uri)
        dslink_url_handle_scheme(url->scheme, &url->port, &url->secure);
    } else {
        // Handle URI
        if (len <= 1) {
            URL_ADDRESS_ASSIGN_URI_END(url->uri)
        } else {
            URL_ADDRESS_SUBSTRING_COPY(url->uri, len)
        }
    }
    return url;

exit:
    dslink_url_free(url);
    return NULL;
}

char *dslink_url_convert_string(Url *url, char *urlStr) {

    strcpy(urlStr,"");
    if(url && url->uri && url->host && url->scheme) {
        sprintf(urlStr,"%s://%s:%u%s",url->scheme,url->host,url->port,url->uri);
    }
    return urlStr;
}


void dslink_url_handle_scheme(const char* scheme,
                              unsigned short *port,
                              uint_fast8_t *secure) {
    if (!scheme) {
        return;
    }
    if (strcmp(scheme, "http") == 0) {
        *port = 80;
        *secure = 0;
    } else if (strcmp(scheme, "https") == 0) {
        *port = 443;
        *secure = 1;
    }
}
void dslink_url_handle_scheme_for_secure(const char *scheme,
                                         uint_fast8_t *secure) {

    if (!scheme) {
        return;
    }

    if (strcmp(scheme, "http") == 0) {
        *secure = 0;
    } else if (strcmp(scheme, "https") == 0) {
        *secure = 1;
    }
}
void dslink_url_free(Url *url) {
    if (!url) {
        return;
    }
    if (url->scheme) {
        dslink_free(url->scheme);
    }
    if (url->host) {
        dslink_free(url->host);
    }
    if (url->uri) {
        dslink_free(url->uri);
    }
    dslink_free(url);
}
