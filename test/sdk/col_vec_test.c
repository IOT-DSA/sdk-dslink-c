#include <stdlib.h>
#include <stdio.h>

#include <dslink/col/vector.h>
#include "cmocka_init.h"

static
void col_vec_init_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10);
    assert_int_equal(vec.capacity, 10);
    assert_int_equal(vec.size, 0);
}

static
void col_vec_append_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10);

    long index = vector_append(&vec, 4711);
    assert_int_equal(index, 0);
    assert_int_equal((int)vector_get(&vec, index), 4711);

    index = vector_append(&vec, 815);
    assert_int_equal(index, 1);
    assert_int_equal((int)vector_get(&vec, index), 815);
}

static
void col_vec_resize_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 2);

    vector_append(&vec, 4711);
    vector_append(&vec, 815);

    assert_int_equal(vec.capacity, 2);
    assert_int_equal(vec.size, 2);

    long index = vector_append(&vec, 42);
    assert_int_equal(index, 2);
    assert_int_equal((int)vector_get(&vec, index), 42);
    assert_int_equal(vec.capacity, 4);
    assert_int_equal(vec.size, 3);
}

static
void col_vec_set_get_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10);

    vector_append(&vec, 4711);
    vector_append(&vec, 815);

    assert_int_equal((int)vector_get(&vec, 0), 4711);
    assert_int_equal((int)vector_get(&vec, 1), 815);

    vector_set(&vec, 0, 42);
    assert_int_equal((int)vector_get(&vec, 0), 42);
    vector_set(&vec, 1, 66);
    assert_int_equal((int)vector_get(&vec, 1), 66);

    assert_null(vector_get(&vec, 2));
}

static
void col_vec_remove_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10);

    vector_append(&vec, 4711);
    vector_append(&vec, 815);
    vector_append(&vec, 42);
    vector_append(&vec, 66);
    assert_int_equal(vec.capacity, 10);
    assert_int_equal(vec.size, 4);

    assert_int_equal((int)vector_get(&vec, 0), 4711);
    assert_int_equal((int)vector_get(&vec, 1), 815);
    assert_int_equal((int)vector_get(&vec, 2), 42);
    assert_int_equal((int)vector_get(&vec, 3), 66);

    vector_remove(&vec, 1);
    assert_int_equal(vec.capacity, 10);
    assert_int_equal(vec.size, 3);

    assert_int_equal((int)vector_get(&vec, 0), 4711);
    assert_int_equal((int)vector_get(&vec, 1), 42);
    assert_int_equal((int)vector_get(&vec, 2), 66);
}

static
void col_vec_iterate_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10);

    vector_append(&vec, 4711);
    vector_append(&vec, 815);
    vector_append(&vec, 42);
    vector_append(&vec, 66);

    uint32_t count = 0;
    dslink_vector_foreach(&vec) {
        switch (count) {
            case 0:
                assert_int_equal((int)data, 4711);
                break;
            case 1:
                assert_int_equal((int)data, 815);
                break;
            case 2:
                assert_int_equal((int)data, 42);
                break;
            case 3:
                assert_int_equal((int)data, 66);
                break;
            default:
                assert_non_null(NULL);
                break;
        }
        ++count;
    }
    dslink_vector_foreach_end();
}

int cmp_int(const void* lhs, const void* rhs)
{
    if((int)lhs == (int)rhs) {
        return 0;
    }
    return -1;
}

static
void col_vec_find_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10);

    vector_append(&vec, 4711);
    vector_append(&vec, 815);
    vector_append(&vec, 42);
    vector_append(&vec, 66);

    int n = 42;
    int idx = vector_find(&vec, n, cmp_int);
    assert_int_equal(idx, 2);
    assert_int_equal((int)vector_get(&vec, idx), 42);
}


int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(col_vec_init_test),
        cmocka_unit_test(col_vec_append_test),
        cmocka_unit_test(col_vec_resize_test),
        cmocka_unit_test(col_vec_set_get_test),
        cmocka_unit_test(col_vec_remove_test),
        cmocka_unit_test(col_vec_iterate_test),
        cmocka_unit_test(col_vec_find_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
