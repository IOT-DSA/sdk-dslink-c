#include <stdlib.h>
#include <stdio.h>

#include <dslink/col/map.h>
#include "cmocka_init.h"

static
void col_map_clear_test(void **state) {
    (void) state;

    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_str_cmp,
                                 dslink_map_str_key_len_cal,
                                 dslink_map_hash_key));

    assert_true(!dslink_map_set(&map, dslink_str_ref("a"), dslink_str_ref("a")));
    assert_true(!dslink_map_set(&map, dslink_str_ref("b"), dslink_str_ref("b")));
    assert_true(!dslink_map_set(&map, dslink_str_ref("c"), dslink_str_ref("c")));
    assert_int_equal(map.size, 3);

    dslink_map_clear(&map);
    assert_int_equal(map.size, 0);
    dslink_map_foreach(&map) {
        // There shouldn't be any elements
        assert_false(1);
    }

    dslink_map_set(&map, dslink_str_ref("1"), dslink_str_ref("2"));
    dslink_map_foreach(&map) {
        assert_string_equal("1", entry->key->data);
        assert_string_equal("2", entry->value->data);
    }

    dslink_map_free(&map);
}

static
void col_map_set_simple_string_test(void **state) {
    (void) state;
    char *inputs[][2] = {
            {"aa/bb", "Hello World"},
            {"bb/bb", "Goodbye World"},
            {"cc/bb", "World Hello"},
            {"dd/bb", "World Goodbye"},
            {NULL, NULL}
    };

    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_str_cmp,
                                 dslink_map_str_key_len_cal,
                                 dslink_map_hash_key));
    int i = 0;
    while (inputs[i][0]) {
        char *key = inputs[i][0];
        char *val = inputs[i][1];

        assert_true(!dslink_map_set(&map, dslink_ref(key, NULL),
                                    dslink_ref(val, NULL)));
        assert_true(dslink_map_contains(&map, key));
        ref_t *stored = dslink_map_get(&map, key);
        assert_non_null(stored);
        assert_string_equal(stored->data, val);

        i++;
    }

    assert_false(dslink_map_contains(&map, "a"));
    dslink_map_free(&map);
}

static
void col_map_set_large_string_entry_test(void **state) {
    (void) state;
    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_str_cmp,
                                 dslink_map_str_key_len_cal,
                                 dslink_map_hash_key));
    const int items = 100;
    for (int n = 0; n < items; n++) {
        size_t len = sizeof(char) * 12;
        char *key = malloc(len);
        char *val = malloc(len);
        assert_true(snprintf(key, len, "%i", n));
        assert_true(snprintf(val, len, "%i %i", n, n));

        assert_true(!dslink_map_set(&map, dslink_ref(key, dslink_free),
                                    dslink_ref(val, dslink_free)));
        assert_true(dslink_map_contains(&map, key));
        ref_t *stored = dslink_map_get(&map, key);
        assert_non_null(stored->data);
        assert_string_equal(stored->data, val);
    }
    assert_int_equal(map.size, items);

    dslink_map_free(&map);
}

static
void col_map_set_simple_uint32_test(void **state) {
    (void) state;
    uint32_t inputs[][2] = {
            {120, 120},
            {250, 201},
            {583, 299},
            {109, 3982},
            {0, 0}
    };

    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_uint32_cmp,
                                 dslink_map_uint32_key_len_cal,
                                 dslink_map_hash_key));
    int i = 0;
    while (inputs[i][0]) {
        uint32_t *key = calloc(1, sizeof(uint32_t));
        *key = inputs[i][0];
        uint32_t *val = calloc(1, sizeof(uint32_t));
        *val = inputs[i][1];

        assert_true(!dslink_map_set(&map, dslink_ref(key, dslink_free),
                                    dslink_ref(val, dslink_free)));
        assert_true(dslink_map_contains(&map, key));
        ref_t *stored = dslink_map_get(&map, key);
        assert_non_null(stored->data);
        assert_int_equal(*((uint32_t *) stored->data), *val);

        i++;
    }

    dslink_map_free(&map);
}

static
void col_map_set_large_uint32_entry_test(void **state) {
    (void) state;
    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_uint32_cmp,
                                 dslink_map_uint32_key_len_cal,
                                 dslink_map_hash_key));
    const uint32_t items = 100;
    for (uint32_t n = 0; n < items; n++) {
        uint32_t *i = calloc(1, sizeof(uint32_t));
        *i = n;

        uint32_t *val = calloc(1, sizeof(uint32_t));
        *val = n * 2;

        assert_true(!dslink_map_set(&map, dslink_ref(i, dslink_free),
                                    dslink_ref(val, dslink_free)));
        assert_true(dslink_map_contains(&map, i));
        ref_t *stored = dslink_map_get(&map, i);
        assert_non_null(stored);
        assert_int_equal(*((uint32_t *) stored->data), *val);
    }
    assert_int_equal(map.size, items);

    dslink_map_free(&map);
}

static
void col_map_remove_large_uint32_entry_test(void **state) {
    (void) state;
    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_uint32_cmp,
                                 dslink_map_uint32_key_len_cal,
                                 dslink_map_hash_key));
    const uint32_t items = 100;
    for (uint32_t n = 0; n < items; n++) {
        uint32_t *i = calloc(1, sizeof(uint32_t));
        *i = n;

        uint32_t *val = calloc(1, sizeof(uint32_t));
        *val = n * 2;

        assert_true(!dslink_map_set(&map, dslink_ref(i, dslink_free),
                                    dslink_ref(val, dslink_free)));
        assert_true(dslink_map_contains(&map, i));
        ref_t *stored = dslink_map_get(&map, i);
        assert_non_null(stored);
        assert_int_equal(*((uint32_t *) stored->data), *val);
    }
    assert_int_equal(map.size, items);

    for (uint32_t n = 0; n < items; n++) {
        dslink_map_remove(&map, &n);
        assert_false(dslink_map_contains(&map, &n));
    }
    assert_int_equal(map.size, 0);
    dslink_map_free(&map);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(col_map_clear_test),
        cmocka_unit_test(col_map_set_simple_string_test),
        cmocka_unit_test(col_map_set_large_string_entry_test),
        cmocka_unit_test(col_map_set_simple_uint32_test),
        cmocka_unit_test(col_map_set_large_uint32_entry_test),
        cmocka_unit_test(col_map_remove_large_uint32_entry_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
