#include <stdlib.h>
#include <stdio.h>

#include <dslink/col/ringbuffer.h>
#include "cmocka_init.h"

static
void col_buf_init_test(void **state) {
    (void) state;

    Ringbuffer rb;
    rb_init(&rb, 10, sizeof(int), NULL);
    assert_int_equal(rb.size, 10);
    assert_int_equal(rb.current, 0);
    assert_int_equal(rb.count, 0);

    rb_free(&rb);
}

static
void col_buf_append_test(void **state) {
    (void) state;

    Ringbuffer rb;
    rb_init(&rb, 3, sizeof(int), NULL);

    int n = 4711;
    int res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    n = 815;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    n = 666;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    n = 42;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 1);
    assert_int_equal(*(int*)rb_front(&rb), 815);

    n = 4711;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 1);
    assert_int_equal(*(int*)rb_front(&rb), 666);

    rb_free(&rb);
}

static
void col_buf_push_n_pop_test(void **state) {
    (void) state;

    Ringbuffer rb;
    rb_init(&rb, 3, sizeof(int), NULL);

    int n = 4711;
    int res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    n = 815;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    n = 666;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    res = rb_pop(&rb);

    n = 42;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 815);

    res = rb_pop(&rb);

    n = 4711;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 666);

    assert_int_equal(rb_count(&rb), 3);

    rb_pop(&rb);
    rb_pop(&rb);
    rb_pop(&rb);

    assert_int_equal(rb_count(&rb), 0);

    n = 42;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 42);

    rb_free(&rb);
}

static
void col_buf_at_test(void **state) {
    (void) state;

    Ringbuffer rb;
    rb_init(&rb, 3, sizeof(int), NULL);

    int n = 4711;
    int res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    n = 815;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    n = 666;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 4711);

    assert_int_equal(*(int*)rb_at(&rb, 0), 4711);
    assert_int_equal(*(int*)rb_at(&rb, 1), 815);
    assert_int_equal(*(int*)rb_at(&rb, 2), 666);

    n = 42;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 1);
    assert_int_equal(*(int*)rb_front(&rb), 815);

    assert_int_equal(*(int*)rb_at(&rb, 0), 815);
    assert_int_equal(*(int*)rb_at(&rb, 1), 666);
    assert_int_equal(*(int*)rb_at(&rb, 2), 42);

    n = 4711;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 1);
    assert_int_equal(*(int*)rb_front(&rb), 666);

    assert_int_equal(*(int*)rb_at(&rb, 0), 666);
    assert_int_equal(*(int*)rb_at(&rb, 1), 42);
    assert_int_equal(*(int*)rb_at(&rb, 2), 4711);

    assert_int_equal(rb_count(&rb), 3);

    rb_pop(&rb);
    rb_pop(&rb);
    rb_pop(&rb);

    assert_int_equal(rb_count(&rb), 0);

    n = 42;
    res = rb_push(&rb, &n);
    assert_int_equal(res, 0);
    assert_int_equal(*(int*)rb_front(&rb), 42);

    assert_int_equal(*(int*)rb_at(&rb, 0), 42);
    assert_null(rb_at(&rb, 1));
    
    rb_free(&rb);
}


int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(col_buf_init_test),
        cmocka_unit_test(col_buf_append_test),
        cmocka_unit_test(col_buf_push_n_pop_test),
        cmocka_unit_test(col_buf_at_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
