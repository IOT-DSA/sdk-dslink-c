#include <ctype.h>
#include <string.h>
#include <time.h>
#include "dslink/mem/mem.h"
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
    char *tmp = dslink_malloc(strSize);
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
    char *tmp = dslink_malloc(len + 1);
    if (!tmp) {
        return NULL;
    }
    memcpy(tmp, str, len);
    tmp[len] = '\0';
    return tmp;
}

static
char *dslink_str_replace_all_rep(const char *haystack,
                                 const char *needle,
                                 const char *replacement,
                                 int shouldDup) {

    char *start = strstr(haystack, needle);
    if (!start) {
        if (shouldDup) {
            return dslink_strdup(haystack);
        } else {
            return (char *) haystack;
        }
    }

    const size_t haystackLen = strlen(haystack);
    const size_t needleLen = strlen(needle);
    const size_t replacementLen = strlen(replacement);
    char *dup = dslink_malloc(haystackLen - needleLen + replacementLen + 1);
    if (!dup) {
        return NULL;
    }

    size_t len = start - haystack;
    memcpy(dup, haystack, len);
    memcpy(dup + len, replacement, replacementLen);
    len += replacementLen;

    size_t remainder = (haystack + haystackLen) - (start + needleLen);
    memcpy(dup + len, start + needleLen, remainder);
    dup[haystackLen - needleLen + replacementLen] = '\0';

    if (!shouldDup) {
        dslink_free((char *) haystack);
    }
    return dslink_str_replace_all_rep(dup, needle, replacement, 0);
}

char *dslink_str_replace_all(const char *haystack,
                             const char *needle,
                             const char *replacement) {
    return dslink_str_replace_all_rep(haystack, needle, replacement, 1);
}

char *dslink_str_escape(const char *data) {
    //TODO other invalid characters
    return dslink_str_replace_all_rep(data, "/", "%2F", 1);
}
char *dslink_str_unescape(const char *data) {
    return dslink_str_replace_all_rep(data, "%2F", "/", 1);
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
