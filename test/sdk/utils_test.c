#include "cmocka_init.h"
#include <dslink/utils.h>
#include <dslink/mem/mem.h>

static
void utils_str_replace_all_test(void **state) {
    (void) state;

    const char *str = "abc_abc_a";
    char *rep = dslink_str_replace_all(str, "a", "123");
    assert_non_null(rep);
    assert_string_equal(rep, "123bc_123bc_123");
    dslink_free(rep);

    str = "abc_abc";
    rep = dslink_str_replace_all(str, "abc", "1");
    assert_non_null(rep);
    assert_string_equal(rep, "1_1");
    dslink_free(rep);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(utils_str_replace_all_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
