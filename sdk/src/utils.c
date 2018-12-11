#include <ctype.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdio.h>

#include "dslink/mem/mem.h"
#include "dslink/utils.h"

#define LOG_TAG "utils"
#include "dslink/log.h"

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

static
int decodeBase16(char c) {
    if (c>='0' && c<='9') {
        return c - '0';
    }
    if (c>='a' && c<='f') {
        return c - ('a' - 10);
    }
    if (c>='A' && c<='F') {
        return c - ('A' - 10);
    }
    return -1;
}

static char encodeBase16(int code) {
    if (code >= 0) {
        if (code < 10) {
            return (char)(code + '0');
        }
        if (code < 16) {
            return (char)(code + ('A'-10));
        }
    }
    return -1;
}

char *dslink_str_escape(const char *data) {
    if (!data) {
        return NULL;
    }
    size_t lenoff = 1;
    const char *search = data;
    while (*search) {
        if (*search <= ',' || *search == '/' || *search == ':' || *search == '=' || *search == '%') {
            lenoff += 2;
        }
        ++search;
    }
    char *rslt = dslink_malloc((search-data) + lenoff);

    char *pt = rslt;
    while (*data) {
        if (*data <= ',' || *data == '/' || *data == ':' || *data == '=' || *search == '%') {
            *pt = '%';
            *(pt + 1) = encodeBase16((*data)>>4);
            *(pt + 2) = encodeBase16((*data)&0xF);
            pt += 3;
        } else {
            *pt = *data;
            ++pt;
        }
        ++data;
    }
    *pt = '\0';
    return rslt;
}

char *dslink_str_unescape(const char *data) {
    if (!data) {
        return NULL;
    }
    char *rslt = dslink_malloc(strlen(data) + 1);
    char *pt = rslt;
    while (*data) {
        if (*data == '%') {
            int c1 = decodeBase16(*(data+1));
            if (c1 > -1) {
                int c2 = decodeBase16(*(data+2));
                if (c2 > -1) {
                    *pt = (char)((c1<<4) + c2);
                    ++pt;
                    data += 3;
                    continue;
                }
            }
        }
        *pt = *data;
        ++pt;
        data++;
    }
    *pt = '\0';
    return rslt;
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
    struct tm result;

    strftime(buf, bufLen,
                    "%Y-%m-%dT%H:%M:%S.000?%z", localtime_r(&nowtime, &result));
    unsigned ms = (unsigned)(now.tv_usec / 1000);
    char msstr[4];

    if (ms > 99) {
        snprintf(msstr, 4, "%u", ms);
        memcpy(buf+20, msstr, 3);
    } else if (ms > 9) {
        snprintf(msstr, 4, "0%u", ms);
        memcpy(buf+20, msstr, 3);
    } else if (ms > 0) {
        snprintf(msstr, 4, "00%u", ms);
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

const char* dslink_checkIpv4Address(const char* address)
{
    const char* host = address;
    if(strcmp("0.0.0.0", address) == 0) {
        static char* localhost = "127.0.0.1";
        host = localhost;
    }

    return host;
}

int sync_json_to_msg_pack(json_t *json_obj, msgpack_packer* pk)
{
#if 0
  // AK: TODO
    char* buf;
    size_t buf_len = 0;
#endif

    switch(json_obj->type)
    {
        case JSON_OBJECT:
            msgpack_pack_map(pk, json_object_size(json_obj));

            const char *key;
            json_t *value;

            void *iter = json_object_iter(json_obj);
            while(iter)
            {
                key = json_object_iter_key(iter);
                value = json_object_iter_value(iter);

                msgpack_pack_str(pk, strlen(key));
                msgpack_pack_str_body(pk, key, strlen(key));

                if(sync_json_to_msg_pack(value, pk) != 1)
                    return 0;

                iter = json_object_iter_next(json_obj, iter);
            }

            break;
        case JSON_ARRAY:
            msgpack_pack_array(pk, json_array_size(json_obj));
            for(size_t i = 0; i < json_array_size(json_obj); i++)
            {
                if(sync_json_to_msg_pack(json_array_get(json_obj, i), pk) != 1)
                    return 0;
            }
            break;
#if 0
	    // AK: TODO
        case JSON_BINARY:
            buf_len = json_binary_length_raw(json_obj);
            buf = (char*) malloc(buf_len);

            buf_len = json_binary_value(json_obj, buf);

            msgpack_pack_bin(pk, buf_len);
            msgpack_pack_bin_body(pk, buf, buf_len);

            free(buf);
            break;
#endif
        case JSON_STRING:
            msgpack_pack_str(pk, json_string_length(json_obj));
            msgpack_pack_str_body(pk, json_string_value(json_obj), json_string_length(json_obj));
            break;
        case JSON_INTEGER:
            msgpack_pack_int(pk, json_integer_value(json_obj));
            break;
        case JSON_REAL:
            msgpack_pack_double(pk, json_real_value(json_obj));
            break;
        case JSON_TRUE:
            msgpack_pack_true(pk);
            break;
        case JSON_FALSE:
            msgpack_pack_false(pk);
            break;
        case JSON_NULL :
            msgpack_pack_nil(pk);
            break;
    }

    return 1;
}

msgpack_sbuffer* dslink_ws_json_to_msgpack(json_t *json_obj)
{
    msgpack_sbuffer* buffer = msgpack_sbuffer_new();
    msgpack_packer* pk = msgpack_packer_new(buffer, msgpack_sbuffer_write);

    if( sync_json_to_msg_pack(json_obj, pk) != 1)
        goto ERROR;

    EXIT:
    msgpack_packer_free(pk);
    return buffer;

    ERROR:
    log_fatal("Cannot convert to msg_pack\n")
    msgpack_sbuffer_free(buffer);
    buffer = NULL;
    goto EXIT;
}



json_t* dslink_ws_msgpack_to_json(msgpack_object* msg_obj)
{
    json_t* json_obj = NULL;
    json_t* temp = NULL;

    char* text;

    switch(msg_obj->type)
    {
        case MSGPACK_OBJECT_NIL:
            json_obj = json_null();
            break;
        case MSGPACK_OBJECT_BOOLEAN:
            json_obj = json_boolean(msg_obj->via.boolean);
            break;
        case MSGPACK_OBJECT_POSITIVE_INTEGER:
            json_obj = json_integer(msg_obj->via.u64);
            break;
        case MSGPACK_OBJECT_NEGATIVE_INTEGER:
            json_obj = json_integer(msg_obj->via.i64);
            break;
        case MSGPACK_OBJECT_FLOAT32:
            json_obj = json_real(msg_obj->via.f64);
            break;
        case MSGPACK_OBJECT_FLOAT:
            json_obj = json_real(msg_obj->via.f64);
            break;
        case MSGPACK_OBJECT_STR:
            json_obj = json_stringn_nocheck(msg_obj->via.str.ptr, msg_obj->via.str.size);
            break;
        case MSGPACK_OBJECT_ARRAY:
            json_obj = json_array();
            for(uint32_t i = 0; i < msg_obj->via.array.size; i++)
            {
                temp = dslink_ws_msgpack_to_json(&msg_obj->via.array.ptr[i]);
                if(temp == NULL)
                    goto ERROR;

                json_array_append(json_obj, temp);
            }
            break;
        case MSGPACK_OBJECT_MAP:
            json_obj = json_object();

            for(uint32_t i = 0; i < msg_obj->via.map.size; i++)
            {
                msgpack_object_kv* kv = &msg_obj->via.map.ptr[i];
                if(kv->key.type != MSGPACK_OBJECT_STR)
                    goto ERROR;

                temp = dslink_ws_msgpack_to_json(&kv->val);
                if(temp == NULL)
                    goto ERROR;

                text = malloc(kv->key.via.str.size + 1);
                memcpy(text, kv->key.via.str.ptr, kv->key.via.str.size);
                text[kv->key.via.str.size] = '\0';
                json_object_set_nocheck(json_obj, text, temp);
                free(text);
            }

            break;
        case MSGPACK_OBJECT_BIN:
	  // AK: TODO
          //  json_obj = json_binaryn_nocheck(msg_obj->via.bin.ptr, msg_obj->via.bin.size);
            break;
        case MSGPACK_OBJECT_EXT:
            log_fatal("Cannot convert json BECAUSE EXT NOT IMPLEMENTED\n");
            goto ERROR;
            break;
    }

    EXIT:
    return json_obj;

    ERROR:
    if(json_obj != NULL)
        json_decref(json_obj);

    json_obj = NULL;
    goto EXIT;
}

const char* dslink_checkIpv6Address(const char* address)
{
    const char* host = address;
    static char* localhost = "::1";

    if(strcmp("::/128", address) == 0 || strcmp("::/0", address) == 0) {
        host = localhost;
    } else {
        size_t span = strspn(address, "0:");
        if(address[span] == '\0') {
            host = localhost;
        }
    }

    return host;
}

int dslink_isipv6address(const char* host)
{
    int i = 0;
    for(; host[i]; host[i]==':' ? i++ : *host++);
    return i>0;
}

