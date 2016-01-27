#include <ctype.h>
#include <string.h>
#include <time.h>
#include "dslink/utils.h"

const char *dslink_strcasestr(const char *haystack, const char *needle) {
    if (!needle || *needle == '\0') {
        return haystack;
    }
    do {
        const char *h = haystack;
        const char *n = needle;
        while ((tolower(*h) == tolower(*n)) && (*h && *n)) {
            h++;
            n++;
        }
        if (*n == '\0') {
            return haystack;
        }
    } while (*haystack++);
    return NULL;
}

int dslink_strcasecmp(const char *a, const char *b) {
    for (;; a++, b++) {
        int d = tolower(*a) - tolower(*b);
        if (d != 0 || !(*a && *b))
            return d;
    }
}

char *dslink_strdup(const char *str) {
    if (!str) {
        return NULL;
    }
    size_t strSize = strlen(str) + 1;
    char *tmp = malloc(strSize);
    if (!tmp) {
        return NULL;
    }
    memcpy(tmp, str, strSize);
    return tmp;
}

char *dslink_strdupl(const char *str, size_t len) {
    if (!str) {
        return NULL;
    }
    char *tmp = malloc(len + 1);
    if (!tmp) {
        return NULL;
    }
    memcpy(tmp, str, len);
    tmp[len] = '\0';
    return tmp;
}

int dslink_str_starts_with(const char *a, const char *b) {
    while (*b) {
        if (*a++ != *b++) {
            return 0;
        }
    }
    return 1;
}

size_t dslink_create_ts(char *buf, size_t bufLen) {
    time_t now = time(NULL);
    return strftime(buf, bufLen,
                    "%Y-%m-%dT%H:%M:%S.000%z", localtime(&now));
}
