#include <ctype.h>
#include <string.h>
#include <time.h>
#include "dslink/utils.h"

void dslink_strlwr(char *str, size_t len) {
    while (len-- > 0) {
        *(str + len) = (char) tolower(*(str + len));
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

size_t dslink_create_ts(char *buf, size_t bufLen) {
    time_t now = time(NULL);
    return strftime(buf, bufLen,
                    "%Y-%m-%dT%H:%M:%S.000%z", localtime(&now));
}
