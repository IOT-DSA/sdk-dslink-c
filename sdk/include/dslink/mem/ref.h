#ifndef SDK_DSLINK_C_REF_H
#define SDK_DSLINK_C_REF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*free_callback)(void *);

typedef struct ref_t {
    int count;
    free_callback deleter;
    void *data;
} ref_t;

ref_t *dslink_ref(void *data, free_callback deleter);
ref_t *dslink_ref_incr(ref_t *ref);
void dslink_ref_decr(ref_t *ref);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_REF_H
