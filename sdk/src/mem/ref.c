#include "dslink/utils.h"
#include "dslink/mem/mem.h"
#include "dslink/mem/ref.h"

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

ref_t *dslink_str_ref(const char *data) {
    return dslink_ref(dslink_strdup(data), dslink_free);
}

ref_t *dslink_strl_ref(const char *data, size_t len) {
    return dslink_ref(dslink_strdupl(data, len), dslink_free);
}

ref_t *dslink_int_ref(uint32_t data) {
    uint32_t *r = dslink_malloc(sizeof(uint32_t));
    *r = data;
    return dslink_ref(r, dslink_free);
}

ref_t *dslink_incref(ref_t *ref) {
    ref->count++;
    return ref;
}

void dslink_decref(ref_t *ref) {
    if (!ref || --ref->count > 0) {
        return;
    }
    if (ref->deleter) {
        ref->deleter(ref->data);
    }
    dslink_free(ref);
}
