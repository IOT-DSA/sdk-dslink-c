#include <stdlib.h>
#include <stdio.h>

#include <dslink/col/vector.h>
#include "cmocka_init.h"

static
void col_vec_init_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10, sizeof(int));
    assert_int_equal(vec.capacity, 10);
    assert_int_equal(vec.size, 0);

    vector_free(&vec);
}


static
void col_vec_free_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10, sizeof(int));

    vector_free(&vec);
    assert_null(vec.data);
    assert_int_equal(vec.capacity, 0);
    assert_int_equal(vec.size, 0);
    assert_int_equal(vec.element_size, sizeof(int));

    int n = 4711;
    long index = vector_append(&vec, &n);
    assert_int_equal(vec.size, 1);
    assert_int_not_equal(vec.capacity, 0);
    assert_int_equal(index, 0);
    assert_int_equal(*(int*)vector_get(&vec, index), 4711);
}

static
void col_vec_append_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10, sizeof(int));

    int n = 4711;
    long index = vector_append(&vec, &n);
    assert_int_equal(index, 0);
    assert_int_equal(*(int*)vector_get(&vec, index), 4711);

    n = 815;
    index = vector_append(&vec, &n);
    assert_int_equal(index, 1);
    assert_int_equal(*(int*)vector_get(&vec, index), 815);

    vector_free(&vec);
}

static
void col_vec_resize_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 2, sizeof(int));

    int n = 4711;
    vector_append(&vec, &n);
    n = 815;
    vector_append(&vec, &n);

    assert_int_equal(vec.capacity, 2);
    assert_int_equal(vec.size, 2);

    n = 42;
    long index = vector_append(&vec, &n);
    assert_int_equal(index, 2);
    assert_int_equal(*(int*)vector_get(&vec, index), 42);
    assert_int_equal(vec.capacity, 4);
    assert_int_equal(vec.size, 3);

    vector_free(&vec);
}

static
void col_vec_set_get_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10, sizeof(int));

    int n = 4711;
    vector_append(&vec, &n);
    n = 815;
    vector_append(&vec, &n);

    assert_int_equal(*(int*)vector_get(&vec, 0), 4711);
    assert_int_equal(*(int*)vector_get(&vec, 1), 815);

    n = 42;
    vector_set(&vec, 0, &n);
    assert_int_equal(*(int*)vector_get(&vec, 0), 42);
    n = 66;
    vector_set(&vec, 1, &n);
    assert_int_equal(*(int*)vector_get(&vec, 1), 66);

    assert_null(vector_get(&vec, 2));

    vector_free(&vec);
}

static
void col_vec_erase_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10, sizeof(int));

    int n = 4711;
    vector_append(&vec, &n);
    n = 815;
    vector_append(&vec, &n);
    n = 42;
    vector_append(&vec, &n);
    n = 66;
    vector_append(&vec, &n);
    assert_int_equal(vec.capacity, 10);
    assert_int_equal(vec.size, 4);

    assert_int_equal(*(int*)vector_get(&vec, 0), 4711);
    assert_int_equal(*(int*)vector_get(&vec, 1), 815);
    assert_int_equal(*(int*)vector_get(&vec, 2), 42);
    assert_int_equal(*(int*)vector_get(&vec, 3), 66);

    vector_erase(&vec, 1);
    assert_int_equal(vec.capacity, 10);
    assert_int_equal(vec.size, 3);

    assert_int_equal(*(int*)vector_get(&vec, 0), 4711);
    assert_int_equal(*(int*)vector_get(&vec, 1), 42);
    assert_int_equal(*(int*)vector_get(&vec, 2), 66);

    vector_free(&vec);
}

static
void col_vec_iterate_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10, sizeof(int));

    int n = 4711;
    vector_append(&vec, &n);
    n = 815;
    vector_append(&vec, &n);
    n = 42;
    vector_append(&vec, &n);
    n = 66;
    vector_append(&vec, &n);

    uint32_t count = 0;
    dslink_vector_foreach(&vec) {
            switch (count) {
                case 0:
                    assert_int_equal(*(int*)data, 4711);
                    break;
                case 1:
                    assert_int_equal(*(int*)data, 815);
                    break;
                case 2:
                    assert_int_equal(*(int*)data, 42);
                    break;
                case 3:
                    assert_int_equal(*(int*)data, 66);
                    break;
                default:
                    assert_non_null(NULL);
                    break;
            }
            ++count;
        }
    dslink_vector_foreach_end();

    vector_free(&vec);
}

int cmp_int(const void* lhs, const void* rhs)
{
    if(*(int*)lhs == *(int*)rhs) {
        return 0;
    } else if(*(int*)lhs > *(int*)rhs) {
        return 1;
    }
    return -1;
}

static
void col_vec_find_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10, sizeof(int));

    int n = 4711;
    vector_append(&vec, &n);
    n = 815;
    vector_append(&vec, &n);
    n = 42;
    vector_append(&vec, &n);
    n = 66;
    vector_append(&vec, &n);

    n = 42;
    int idx = vector_find(&vec, &n, cmp_int);
    assert_int_equal(idx, 2);
    assert_int_equal(*(int*)vector_get(&vec, idx), 42);

    n = 88;
    idx = vector_find(&vec, &n, cmp_int);
    assert_int_equal(idx, -1);

    idx = vector_find(NULL, &n, cmp_int);
    assert_int_equal(idx, -1);

    vector_free(&vec);
}

static
void col_vec_count_test(void **state) {
    (void) state;

    assert_int_equal(vector_count(NULL), 0);

    Vector vec;
    vector_init(&vec, 10, sizeof(int));

    assert_int_equal(vector_count(&vec), 0);

    int n = 4711;
    vector_append(&vec, &n);
    n = 815;
    vector_append(&vec, &n);
    n = 42;
    vector_append(&vec, &n);
    n = 66;
    vector_append(&vec, &n);

    assert_int_equal(vector_count(&vec), 4);

    vector_free(&vec);
}

static
void col_vec_add_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 10, sizeof(int));

    int n = 1;
    for(; n < 1024; ++n) {
        vector_append(&vec, &n);
    }

    vector_free(&vec);
}

static
void col_vec_binary_search_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 512, sizeof(int));

    int n = 2;
    for(; n <= 1024; n += 2) {
        vector_append(&vec, &n);
    }
    assert_int_equal(vector_count(&vec), 512);

    n = 42;
    int idx = vector_binary_search(&vec, &n, cmp_int);
    assert_int_equal(idx, 20);
    assert_int_equal(*(int*)vector_get(&vec, idx), n);

    n = 41;
    idx = vector_binary_search( &vec, &n, cmp_int );
    assert_int_equal(idx, -1);

    n = 0;
    idx = vector_binary_search( &vec, &n, cmp_int );
    assert_int_equal(idx, -1);

    n = 1025;
    idx = vector_binary_search( &vec, &n, cmp_int );
    assert_int_equal(idx, -1);

    vector_free(&vec);
}

static
void col_vec_binary_search_range_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 512, sizeof(int));

    int n = 2;
    for(; n <= 1024; n += 2) {
        vector_append(&vec, &n);
    }
    assert_int_equal(vector_count(&vec), 512);

    n = 42;
    int idx = vector_binary_search_range(&vec, &n, cmp_int, 0, 512);
    assert_int_equal(idx, 20);
    assert_int_equal(*(int*)vector_get(&vec, idx), n);

    assert_int_equal( vector_binary_search_range(&vec, &n, cmp_int, 0, idx+1), idx );
    assert_int_equal( vector_binary_search_range(&vec, &n, cmp_int, idx, 512), idx );
    assert_int_equal( vector_binary_search_range(&vec, &n, cmp_int, idx/2, 512), idx );
    assert_int_equal( vector_binary_search_range(&vec, &n, cmp_int, idx, idx+1), idx );
    assert_int_equal( vector_binary_search_range(&vec, &n, cmp_int, 0, 2*512), idx );

    assert_int_equal( vector_binary_search_range(&vec, &n, cmp_int, 0, idx), -1 );
    assert_int_equal( vector_binary_search_range(&vec, &n, cmp_int, idx, idx), -1 );
    assert_int_equal( vector_binary_search_range(&vec, &n, cmp_int, idx+1, 512), -1 );

    n = 41;
    idx = vector_binary_search_range( &vec, &n, cmp_int, 0, 512 );
    assert_int_equal(idx, -1);

    n = 0;
    idx = vector_binary_search_range( &vec, &n, cmp_int, 0, 512 );
    assert_int_equal(idx, -1);

    n = 1025;
    idx = vector_binary_search_range( &vec, &n, cmp_int, 0, 512 );
    assert_int_equal(idx, -1);

    vector_free(&vec);
}

static
void col_vec_upper_bound_test(void **state) {
    (void) state;

    int n = 2;

    assert_int_equal( vector_upper_bound(NULL, &n, cmp_int), 0 );

    Vector vec;
    vector_init(&vec, 512, sizeof(int));

    assert_int_equal( vector_upper_bound(&vec, &n, cmp_int), 0 );

    for(; n <= 1024; n += 2) {
        vector_append(&vec, &n);
    }
    assert_int_equal(vector_count(&vec), 512);


    n = 42;
    int idx = vector_upper_bound(&vec, &n, cmp_int);
    assert_int_equal(idx, 21);
    assert_int_equal(*(int*)vector_get(&vec, idx), 44);

    n = 41;
    idx = vector_upper_bound( &vec, &n, cmp_int );
    assert_int_equal(idx, 20);
    assert_int_equal(*(int*)vector_get(&vec, idx), 42);

    n = 0;
    idx = vector_upper_bound( &vec, &n, cmp_int );
    assert_int_equal(idx, 0);

    n = 1025;
    idx = vector_upper_bound( &vec, &n, cmp_int );
    assert_int_equal(idx, 512);

    vector_free(&vec);
}

static
void col_vec_upper_bound_range_test(void **state) {
    (void) state;

    Vector vec;
    vector_init(&vec, 512, sizeof(int));

    int n = 2;
    for(; n <= 1024; n += 2) {
        vector_append(&vec, &n);
    }
    assert_int_equal(vector_count(&vec), 512);

    n = 42;
    int idx = vector_upper_bound_range(&vec, &n, cmp_int, 0, 512);
    assert_int_equal(idx, 21);
    assert_int_equal(*(int*)vector_get(&vec, idx), 44);

    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, 0, idx+1), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx, 512), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx/2, 512), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx, idx+1), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, 0, 2*512), idx );

    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, 0, idx), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx, idx), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx+1, 512), idx+1 );

    n = 41;
    idx = vector_upper_bound_range( &vec, &n, cmp_int, 0, 512 );
    assert_int_equal(idx, 20);
    assert_int_equal(*(int*)vector_get(&vec, idx), 42);

    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, 0, idx+1), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx, 512), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx/2, 512), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx, idx+1), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, 0, 2*512), idx );

    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, 0, idx), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx, idx), idx );
    assert_int_equal( vector_upper_bound_range(&vec, &n, cmp_int, idx+1, 512), idx+1 );

    n = 0;
    idx = vector_upper_bound_range( &vec, &n, cmp_int, 0, 512 );
    assert_int_equal(idx, 0);

    n = 1025;
    idx = vector_upper_bound_range( &vec, &n, cmp_int, 0, 512 );
    assert_int_equal(idx, 512);

    vector_free(&vec);
}

static
void col_vec_range_erase_test(void **state) {
    (void) state;

    {
        Vector vec;
        vector_init(&vec, 10, sizeof(int));

        int n = 0;
        for(; n < 1024; ++n) {
            vector_append(&vec, &n);
        }

        vector_erase_range(&vec, 0, 1000);

        assert_int_equal(vector_count(&vec), 24);

        assert_int_equal(*(int*)vector_get(&vec, 0), 1000);
        assert_int_equal(*(int*)vector_get(&vec, 23), 1023);

        vector_free(&vec);
    }
    {
        Vector vec;
        vector_init(&vec, 10, sizeof(int));

        int n = 0;
        for(; n < 1024; ++n) {
            vector_append(&vec, &n);
        }

        vector_erase_range(&vec, 500, 901);

        assert_int_equal(vector_count(&vec), 623);
        assert_int_equal(*(int*)vector_get(&vec, 0), 0);
        assert_int_equal(*(int*)vector_get(&vec, 622), 1023);

        vector_free(&vec);
    }
    {
        Vector vec;
        vector_init(&vec, 10, sizeof(int));

        int n = 0;
        for(; n < 1024; ++n) {
            vector_append(&vec, &n);
        }

        vector_erase_range(&vec, 500, 2001);

        assert_int_equal(vector_count(&vec), 500);
        assert_int_equal(*(int*)vector_get(&vec, 0), 0);
        assert_int_equal(*(int*)vector_get(&vec, 499), 499);

        vector_free(&vec);
    }
    {
        Vector vec;
        vector_init(&vec, 10, sizeof(int));

        int n = 1;
        for(; n < 1024; ++n) {
            vector_append(&vec, &n);
        }

        assert_int_equal(vector_erase_range(&vec, 2000, 500), -1);

        vector_free(&vec);
    }
}


static int int_equal_hundreths(const void *lhs, const void *rhs)
{
    int lhsHundredths = (*(int*)lhs) / 100;
    int rhsHundredths = (*(int*)rhs) / 100;

    if ( lhsHundredths < rhsHundredths ) {
        return -1;
    } else if ( lhsHundredths > rhsHundredths ) {
        return +1;
    } else {
        return 0;
    }
}


static
void col_vec_remove_if_test(void **state)
{
    (void) state;

    Vector vec;
    vector_init(&vec, 512, sizeof(int));

    int n = 2;
    for(; n <= 1024; n += 2) {
        vector_append(&vec, &n);
    }
    assert_int_equal(vector_count(&vec), 512);

    // Remove 49 elements at the beginning of the vector
    n = 0;
    uint32_t idx = vector_remove_if( &vec, &n, &int_equal_hundreths);
    assert_int_equal( idx, 463 );
    assert_int_equal( vector_erase_range( &vec, idx, vector_count(&vec)), 0 );
    // Second remove should do nothing
    assert_int_equal( vector_remove_if( &vec, &n, &int_equal_hundreths), 463 );
    for (uint32_t i = 0; i < 463; ++i) {
        assert_int_equal( *(int*)vector_get( &vec, i), 2*i+100 );
    }

    // Remove  13 elements at the end of the vector
    n = 1000;
    idx = vector_remove_if( &vec, &n, &int_equal_hundreths);
    assert_int_equal( idx, 450 );
    assert_int_equal( vector_erase_range( &vec, idx, vector_count(&vec)), 0 );
    // Second remove should do nothing
    assert_int_equal( vector_remove_if( &vec, &n, &int_equal_hundreths), 450 );
    // Now check, if everything is still valid
    for (uint32_t i = 0; i < 450; ++i) {
        assert_int_equal( *(int*)vector_get( &vec, i), 2*i+100 );
    }

    // Remove 50 Elements in the middle of the vector.
    n = 400;
    idx = vector_remove_if( &vec, &n, &int_equal_hundreths);
    assert_int_equal( idx, 400 );
    assert_int_equal( vector_erase_range( &vec, idx, vector_count(&vec)), 0 );
    // Second remove should do nothing
    assert_int_equal( vector_remove_if( &vec, &n, &int_equal_hundreths), 400 );
    // Now check, if everything is still valid
    for (uint32_t i = 0; i < 149; ++i) {
        assert_int_equal( *(int*)vector_get( &vec, i), 2*i+100 );
    }
    for (uint32_t i = 150; i < 400; ++i) {
        assert_int_equal( *(int*)vector_get( &vec, i), 2*i+200 );
    }
}


int main() {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(col_vec_init_test),
            cmocka_unit_test(col_vec_free_test),
            cmocka_unit_test(col_vec_append_test),
            cmocka_unit_test(col_vec_resize_test),
            cmocka_unit_test(col_vec_set_get_test),
            cmocka_unit_test(col_vec_erase_test),
            cmocka_unit_test(col_vec_remove_if_test),
            cmocka_unit_test(col_vec_iterate_test),
            cmocka_unit_test(col_vec_find_test),
            cmocka_unit_test(col_vec_count_test),
            cmocka_unit_test(col_vec_add_test),
            cmocka_unit_test(col_vec_binary_search_test),
            cmocka_unit_test(col_vec_binary_search_range_test),
            cmocka_unit_test(col_vec_upper_bound_test),
            cmocka_unit_test(col_vec_upper_bound_range_test),
            cmocka_unit_test(col_vec_range_erase_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}