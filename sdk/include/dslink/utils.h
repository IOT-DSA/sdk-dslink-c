#ifndef SDK_DSLINK_C_UTILS_H
#define SDK_DSLINK_C_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>

#define DSLINK_CHECKED_EXEC(func, val) \
    if (val) func(val)

void dslink_strlwr(char *str, size_t len);
char *dslink_strdup(const char *str);
size_t dslink_create_ts(char *buf, size_t bufLen);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_UTILS_H
