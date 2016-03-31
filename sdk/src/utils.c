#include <ctype.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>

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
                                 const size_t needleLen,
                                 const char *replacement,
                                 const size_t replacementLen,
                                 const int shouldDup) {

    char *start = strstr(haystack, needle);
    if (!start) {
        if (shouldDup) {
            return dslink_strdup(haystack);
        } else {
            return (char *) haystack;
        }
    }

    const size_t haystackLen = strlen(haystack);
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
    return dslink_str_replace_all_rep(dup, needle, needleLen,
                                      replacement, replacementLen, 0);
}

char *dslink_str_replace_all(const char *haystack,
                             const char *needle,
                             const char *replacement) {
    size_t needleLen = strlen(needle);
    size_t replacementLen = strlen(replacement);
    return dslink_str_replace_all_rep(haystack, needle, needleLen,
                                      replacement, replacementLen, 1);
}

char *dslink_str_escape(const char *data) {
    //TODO other invalid characters
    return dslink_str_replace_all(data, "/", "%2F");
}

char *dslink_str_unescape(const char *data) {
    return dslink_str_replace_all(data, "%2F", "/");
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
    struct timeval now;
    gettimeofday(&now, NULL);
    time_t nowtime = now.tv_sec;

    strftime(buf, bufLen,
                    "%Y-%m-%dT%H:%M:%S.000?%z", localtime(&nowtime));
    unsigned ms = (unsigned)(now.tv_usec / 1000);
    char msstr[4];

    if (ms > 99) {
        snprintf(msstr, 4, "%d", ms);
        memcpy(buf+20, msstr, 3);
    } else if (ms > 9) {
        snprintf(msstr, 4, "0%d", ms);
        memcpy(buf+20, msstr, 3);
    } else if (ms > 0) {
        snprintf(msstr, 4, "00%d", ms);
        memcpy(buf+20, msstr, 3);
    }
    // change timezone format from ?+0000 to +00:00
    buf[23] = buf[24];
    buf[24] = buf[25];
    buf[25] = buf[26];
    buf[26] = ':';
    return 29;
}

int dslink_sleep(long ms) {
    struct timespec req;

    if (ms > 999) {
        req.tv_sec = ms / 1000;
        req.tv_nsec = (ms - (req.tv_sec * 1000)) * 1000000;
    } else {
        req.tv_sec = 0;
        req.tv_nsec = ms * 1000000;
    }

    return nanosleep(&req, NULL);
}
