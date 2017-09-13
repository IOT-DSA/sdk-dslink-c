#include <stdlib.h>

#include "dslink/mem/mem.h"
#include "dslink/col/vector.h"

#include <string.h>


int vector_init(Vector* vec, uint32_t initial_size)
{
    if(!vec) {
        return -1;
    }
    vec->data = dslink_calloc(initial_size, sizeof(vec->data));
    if(!vec->data) {
        return -1;
    }

    vec->capacity = initial_size;
    vec->size = 0;

    return 0;
}

static int vector_resize(Vector* vec)
{
    if(!vec) {
        return -1;
    }
    if(vec->size >= vec->capacity) {
        uint8_t cap = vec->capacity * 2;
        void** data = dslink_realloc(vec->data, cap*sizeof(vec->data));
        if(!data) {
            return -1;
        }
        vec->capacity = cap;
    }

    return 0;
}

long vector_append(Vector* vec, void* data)
{
    if(!vec) {
        return -1;
    }
    if(vec->size >= vec->capacity) {
        // not enough room left, resize
        if(vector_resize(vec) != 0) {
            return -1;
        }
    }
    vec->data[vec->size++] = data;

    return vec->size-1;
}

int vector_set(Vector* vec, uint32_t index, void* data)
{
    if(!vec || index >= vec->size) {
        return -1;
    }
    vec->data[index] = data;
    return 0;
}

void* vector_get(Vector* vec, uint32_t index)
{
    if(!vec || index >= vec->size) {
        return NULL;
    }
    return vec->data[index];
}

int vector_remove(Vector* vec, uint32_t index)
{
    if(!vec || index >= vec->size) {
        return -1;
    }
    if(index != vec->size-1) {
        memmove(&vec->data[index], &vec->data[index+1], (vec->size-(index+1))*sizeof(vec->data));
    }
    --(vec->size);

    return 0;
}

int vector_find(Vector* vec, void* data, vector_comparison_fn_type cmp_fn)
{
    if(!vec && vec->size > 0) {
        return -1;
    }

    for(uint32_t n = 0; n < vec->size; ++n) {
        if(cmp_fn(data, vec->data[n]) == 0) {
            return n;
        }
    }

    return 0;
}

int vector_free(Vector* vec)
{
    if(!vec) {
        return -1;
    }

    dslink_free(vec->data);
    return 0;
}
