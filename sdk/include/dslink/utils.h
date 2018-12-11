#ifndef SDK_DSLINK_C_UTILS_H
#define SDK_DSLINK_C_UTILS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <jansson.h>
#include <msgpack.h>

#define DSLINK_CHECKED_EXEC(func, val) \
    if (val) func(val)

const char *dslink_strcasestr(const char *haystack, const char *needle);
int dslink_strcasecmp(const char *a, const char *b);
char *dslink_strdup(const char *str);
char *dslink_strdupl(const char *str, size_t len);
int dslink_str_starts_with(const char *a, const char *b);
char *dslink_str_replace_all(const char *haystack,
                             const char *needle,
                             const char *replacement);
char *dslink_str_escape(const char *data);
char *dslink_str_unescape(const char *data);

size_t dslink_create_ts(char *buf, size_t bufLen);

int dslink_sleep(long ms);

int sync_json_to_msg_pack(json_t *json_obj, msgpack_packer* pk);

msgpack_sbuffer* dslink_ws_json_to_msgpack(json_t *json_obj);
json_t* dslink_ws_msgpack_to_json(msgpack_object* obj);

const char* dslink_checkIpv4Address(const char* address);
const char* dslink_checkIpv6Address(const char* address);
int dslink_isipv6address(const char* host);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_UTILS_H
