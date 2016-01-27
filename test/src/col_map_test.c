#include "cmocka_init.h"
#include <stdlib.h>
#include <dslink/col/map.h>
#include <stdio.h>

static
void col_map_set_simple_string_test(void **state) {
    (void) state;
    char *inputs[][2] = {
            {"A", "Hello World"},
            {"B", "Goodbye World"},
            {"C", "World Hello"},
            {"D", "World Goodbye"},
            {NULL, NULL}
    };

    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_str_cmp,
                                 dslink_map_str_key_len_cal));
    int i = 0;
    while (inputs[i] && inputs[i][0] && inputs[i][1]) {
        char *key = inputs[i][0];
        char *val = inputs[i][1];

        void *tmp = val;
        assert_true(!dslink_map_set(&map, key, &tmp));
        assert_true(dslink_map_contains(&map, key));
        assert_null(tmp);
        char *stored = dslink_map_get(&map, key);
        assert_non_null(stored);
        assert_string_equal(stored, val);

        i++;
    }

    DSLINK_MAP_FREE(&map, {});
}

static
void col_map_set_large_string_entry_test(void **state) {
    (void) state;
    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_str_cmp,
                                 dslink_map_str_key_len_cal));
    for (int n = 0; n < 9000; n++) {
        size_t len = sizeof(char) * 12;
        char *key = malloc(len);
        char *val = malloc(len);
        assert_true(snprintf(key, len, "%i", n));
        assert_true(snprintf(val, len, "%i %i", n, n));

        void *tmp = val;

        assert_true(!dslink_map_set(&map, key, &tmp));
        assert_true(dslink_map_contains(&map, key));
        assert_null(tmp);
        char *stored = dslink_map_get(&map, key);
        assert_non_null(stored);
        assert_string_equal(stored, val);
    }

    DSLINK_MAP_FREE(&map, {
        free(entry->key);
        free(entry->value);
    });
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
                                 dslink_map_uint32_key_len_cal));
    int i = 0;
    while (inputs[i] && inputs[i][0] && inputs[i][1]) {
        uint32_t *key = calloc(1, sizeof(uint32_t));
        *key = inputs[i][0];
        uint32_t *val = calloc(1, sizeof(uint32_t));
        *val = inputs[i][1];

        void *tmp = val;
        assert_true(!dslink_map_set(&map, key, &tmp));
        assert_true(dslink_map_contains(&map, key));
        assert_null(tmp);
        uint32_t *stored = dslink_map_get(&map, key);
        assert_non_null(stored);
        assert_int_equal(stored, val);

        i++;
    }

    DSLINK_MAP_FREE(&map, {
        free(entry->key);
        free(entry->value);
    });
}

static
void col_map_set_large_uint32_entry_test(void **state) {
    (void) state;
    Map map;
    assert_true(!dslink_map_init(&map, dslink_map_uint32_cmp,
                                 dslink_map_uint32_key_len_cal));
    for (int n = 0; n < 9000; n++) {
        uint32_t *i = calloc(1, sizeof(uint32_t));
        *i = (uint32_t) n;

        uint32_t *val = calloc(1, sizeof(uint32_t));
        *val = (uint32_t) (n * 2);

        void *tmp = val;
        assert_true(!dslink_map_set(&map, i, &tmp));
        assert_true(dslink_map_contains(&map, i));
        assert_null(tmp);
        uint32_t *stored = dslink_map_get(&map, i);
        assert_non_null(stored);
        assert_int_equal(stored, val);
    }

    DSLINK_MAP_FREE(&map, {
        free(entry->key);
        free(entry->value);
    });
}

int main(void) {
    const struct CMUnitTest tests[] = {
            cmocka_unit_test(col_map_set_simple_string_test),
            cmocka_unit_test(col_map_set_large_string_entry_test),
            cmocka_unit_test(col_map_set_simple_uint32_test),
            cmocka_unit_test(col_map_set_large_uint32_entry_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
