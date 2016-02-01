#ifndef SDK_DSLINK_C_REF_H
#define SDK_DSLINK_C_REF_H

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ref_t {
    int count;
    void *data;
} ref_t;

inline
ref_t *dslink_ref(void *data) {
    if (!data) {
        return NULL;
    }
    ref_t *ref = dslink_malloc(sizeof(ref_t));
    if (!ref) {
        return NULL;
    }
    ref->count = 1;
    ref->data = data;
    return ref;
}

inline
ref_t *dslink_ref_incr(ref_t *ref) {
    ref->count++;
    return ref;
}

inline
void *dslink_ref_decr(ref_t *ref) {
    if (!ref || --ref->count > 0) {
        return NULL;
    }
    void *tmp = ref->data;
    if (ref->count <= 0) {
        dslink_free(ref);
    }
    return tmp;
}

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_REF_H
