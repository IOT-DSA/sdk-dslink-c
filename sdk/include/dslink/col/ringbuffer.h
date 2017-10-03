#ifndef SDK_DSLINK_C_RINGBUFFER_H
#define SDK_DSLINK_C_RINGBUFFER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include "dslink/mem/mem.h"

    typedef void (*rb_cleanup_fn_type)(void *);

    /// Defines the structure of a ringbuffer.
    typedef struct {
        uint32_t size;
        uint32_t current;
        uint32_t count;
        void* data;
        size_t element_size;
        rb_cleanup_fn_type cleanup_fn;
    } Ringbuffer;


    /// Initializes a ringbuffer.
    /// @param rb The ringbuffer to initialize
    /// @param size The initial element capacity of the ringbuffer
    /// @param element_size Size of a single element.
    /// @param cleanup_fn
    /// @return 0 if the ringbuffer could be initialized successfully, otherwise -1
    int rb_init(Ringbuffer* rb, uint32_t size, size_t element_size, rb_cleanup_fn_type cleanup_fn);

    /// Returns the number of elements in the ringbuffer.
    /// @param rb The ringbuffer to initialize
    /// @return The number of elements in the buffer
    int rb_count(const Ringbuffer* rb);

    /// Adds a value to the end of the ringbuffer, also known as push back. Will overwrite oldest value, if the buffer
    /// was already full.
    /// @param rb The ringbuffer
    /// @param data A pointer to the value to add. The value will be copied into the ringbuffer.
    /// @return 0 upon success, -1 otherwise, 1 is returned, if a previously added value was overwritten
    int rb_push(Ringbuffer* rb, void* data);

    /// Gets the first value of the ringbuffer.
    /// @param rb The ringbuffer
    /// @return A pointer to the value or NULL if the ringbuffer has no values
    void* rb_front(const Ringbuffer* rb);

    /// Gets the value at the index of the ringbuffer.
    /// @param rb The ringbuffer
    /// @param index The index to get the value for
    /// @return A pointer to the value or NULL if the index is out of range
    void* rb_at(const Ringbuffer* rb, uint32_t index);

    /// Removes the first value of the ringbuffer.
    /// @param rb The ringbuffer
    /// @return 0 upon success, -1 otherwise
    int rb_pop(Ringbuffer* rb);

    /// Frees the internally allocated memory of the ringbuffer. Does not free the memory pointed to by the elements.
    /// @param rb The ringbuffer
    /// @return 0 upon success, -1 otherwise
    int rb_free(Ringbuffer* rb);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_RINGBUFFER_H
