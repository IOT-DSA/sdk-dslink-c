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

inline
ref_t *dslink_ref(void *data, free_callback deleter) {
    if (!data) {
        return NULL;
    }
    ref_t *ref = dslink_malloc(sizeof(ref_t));
    if (!ref) {
        return NULL;
    }
    ref->count = 1;
    ref->deleter = deleter;
    ref->data = data;
    return ref;
}

inline
ref_t *dslink_ref_incr(ref_t *ref) {
    ref->count++;
    return ref;
}

inline
void dslink_ref_decr(ref_t *ref) {
    if (!ref || --ref->count > 0) {
        return;
    }
    ref->deleter(ref->data);
    dslink_free(ref);
}

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_REF_H
