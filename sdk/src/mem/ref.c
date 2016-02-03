#include <stddef.h>
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

ref_t *dslink_ref_incr(ref_t *ref) {
    ref->count++;
    return ref;
}

void dslink_ref_decr(ref_t *ref) {
    if (!ref || --ref->count > 0) {
        return;
    }
    if (ref->deleter) {
        ref->deleter(ref->data);
    }
    dslink_free(ref);
}
