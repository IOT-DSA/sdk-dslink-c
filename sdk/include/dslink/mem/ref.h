#ifndef SDK_DSLINK_C_REF_H
#define SDK_DSLINK_C_REF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

typedef void (*free_callback)(void *);

typedef struct ref_t {
    int count;
    free_callback deleter;
    void *data;
} ref_t;

ref_t *dslink_ref(void *data, free_callback deleter);
ref_t *dslink_str_ref(const char *data);
ref_t *dslink_strl_ref(const char *data, size_t len);
ref_t *dslink_int_ref(uint32_t data);

ref_t *dslink_incref(ref_t *ref);
void dslink_decref(ref_t *ref);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_REF_H
