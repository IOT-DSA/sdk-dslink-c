#ifndef SDK_DSLINK_C_VECTOR_H
#define SDK_DSLINK_C_VECTOR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdlib.h>
#include <stdint.h>

#include "dslink/mem/mem.h"

    typedef int vector_comparison_fn_type(const void *, const void *);

    /// Defines the structure of a vector.
    typedef struct {
        uint32_t size;
        uint32_t capacity;
        void* data;
        size_t element_size;
    } Vector;

#define dslink_vector_foreach(vector) {\
uint32_t n = 0;\
for (void* data = (vector)->data; n < (vector)->size; ++n, data = (char*)(vector)->data+(n*(vector)->element_size))

#define dslink_vector_foreach_end() }

    /// Initializes a vector.
    /// @param vec The vector to initialize
    /// @param initial_size The initial element capacity of the vector
    /// @param element_size Size of a single element.
    /// @return 0 if the vector could be initialized successfully, otherwise -1
    int vector_init(Vector* vec, uint32_t initial_size, size_t element_size);

    uint32_t vector_count(const Vector* vec);

    /// Adds a value to the end of the vector, also known as push back.
    /// @param vec The vector
    /// @param data A pointer to the value to add. The value will be copied into the vector.
    /// @return The index (>= 0) upon success, -1 otherwise
    long vector_append(Vector* vec, void* data);

    /// Sets a new value for the element at index. If the index is not in range, an error will be returned and the
    /// vector remains unchanged.
    /// @param vec The vector
    /// @param index The index to set the value for
    /// @param data A pointer to the value to set. The value will be copied into the vector.
    /// @return 0 upon success, -1 otherwise
    int vector_set(Vector* vec, uint32_t index, void* data);

    /// Gets the value at the index. If the index is not in range, an error will be returned
    /// @param vec The vector
    /// @param index The index to get the value for
    /// @return A pointer to the value or NULL if the index is out of range.
    void* vector_get(const Vector* vec, uint32_t index);

    /// Removes the value at the index and reorganizes the vector to fill the gap, thus invalidating all previous
    /// indexes. If the index is not in range, an error will be returned and the
    /// vector remains unchanged.
    /// @param vec The vector
    /// @param index The index to remove the value from
    /// @return 0 upon success, -1 otherwise
    int vector_remove(Vector* vec, uint32_t index);

    /// Removes the values between the [lower, upper] range and reorganizes the vector to fill the gap, thus
    /// invalidating all previous indexes. If the [lower, upper] range is not in range, an error will be returned and the
    /// vector remains unchanged.
    /// @param vec The vector
    /// @param lower The lower bound to remove from
    /// @param upper The upper bound to remove from
    /// @return 0 upon success, -1 otherwise
    int vector_remove_range(Vector* vec, uint32_t lower, uint32_t upper);

    /// Searches the vector for the data using the given comparison function.
    /// @param vec The vector
    /// @param data The data to find
    /// @param cmp_fn The compare function to use
    /// @return The index (>= 0) of the value if found, -1 otherwise
    long vector_find(const Vector* vec, void* data, vector_comparison_fn_type cmp_fn);

    /// Searches the vector for the data using the given comparison function and a binary search algorithm. The vector
    /// has to be sorted in order to work.
    /// @param vec The vector
    /// @param data The data to find
    /// @param cmp_fn The compare function to use
    /// @return The index (>= 0) of the value if found, -1 otherwise
    long vector_binary_search(const Vector* vec, void* data, vector_comparison_fn_type cmp_fn);

    /// Searches a range of vector for the data using the given comparison function and a binary search algorithm. 
    /// The vector has to be sorted in order to work.
    /// @param vec The vector
    /// @param data The data to find
    /// @param cmp_fn The compare function to use
    /// @param lower The lowest index of the range to search in
    /// @param upper The upper (excluded) index of the range to search in
    /// @return The index in the range [lower,upper) of the value if found, -1 otherwise
    long vector_binary_search_range(const Vector* vec, void* data, vector_comparison_fn_type cmp_fn, 
				 uint32_t lower, uint32_t upper);

    /// Searches the vector for the data using the given comparison function and a binary search algorithm. The vector
    /// has to be sorted in order to work.
    /// @param vec The vector
    /// @param data The data to find
    /// @param cmp_fn The compare function to use
    /// @return The index (>= 0) of the value if found, -1 otherwise
    uint32_t vector_upper_bound(const Vector* vec, void* data, vector_comparison_fn_type cmp_fn);

    /// Searches a range of vector for the data using the given comparison function and a binary search algorithm. 
    /// The vector has to be sorted in order to work.
    /// @param vec The vector
    /// @param data The data to find
    /// @param cmp_fn The compare function to use
    /// @param lower The lowest index of the range to search in
    /// @param upper The upper (excluded) index of the range to search in
    /// @return The index in the range [lower,upper) of the value if found, -1 otherwise
    uint32_t vector_upper_bound_range(const Vector* vec, void* data, vector_comparison_fn_type cmp_fn, 
				      uint32_t lower, uint32_t upper);

    /// Frees the internally allocated memory of the vector. Does not free the memory pointed to by the elements.
    /// @param vec The vector
    /// @return 0 upon success, -1 otherwise
    int vector_free(Vector* vec);

#ifdef __cplusplus
}
#endif

#endif // SDK_DSLINK_C_VECTOR_H
