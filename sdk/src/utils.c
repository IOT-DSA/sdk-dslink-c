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

size_t dslink_create_ts(char *buf, size_t bufLen) {
    time_t now = time(NULL);
    return strftime(buf, bufLen,
                    "%Y-%m-%dT%H:%M:%S.000%z", localtime(&now));
}
