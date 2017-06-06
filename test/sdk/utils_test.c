#include "cmocka_init.h"
#include <dslink/utils.h>
#include <dslink/url.h>
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

static
void url_parse_test(void **state)
{
    (void) state;

    {
        const char address[] = "http://127.0.0.1:8100/conn";

        Url* url = dslink_url_parse(address);
        assert_non_null(url);
        assert_string_equal("127.0.0.1", url->host);
        assert_string_equal("http", url->scheme);
        assert_false(url->secure);
        assert_true(8100u == url->port);
        assert_string_equal("/conn", url->uri);
    }
    {
        const char address[] = "https://10.228.24.43:8463/conn";

        Url* url = dslink_url_parse(address);
        assert_non_null(url);
        assert_string_equal("10.228.24.43", url->host);
        assert_string_equal("https", url->scheme);
        assert_true(url->secure);
        assert_true(8463u == url->port);
        assert_string_equal("/conn", url->uri);
    }
    {
        const char address[] = "http://[::1]:8100/conn";

        Url* url = dslink_url_parse(address);
        assert_non_null(url);
        assert_string_equal("::1", url->host);
        assert_string_equal("http", url->scheme);
        assert_false(url->secure);
        assert_true(8100u == url->port);
        assert_string_equal("/conn", url->uri);
    }
    {
        const char address[] = "https://[2001:420:44e7:1300:b039:6611:2e10:e963]:8463/conn";

        Url* url = dslink_url_parse(address);
        assert_non_null(url);
        assert_string_equal("2001:420:44e7:1300:b039:6611:2e10:e963", url->host);
        assert_string_equal("https", url->scheme);
        assert_true(url->secure);
        assert_true(8463u == url->port);
        assert_string_equal("/conn", url->uri);
    }
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(utils_str_replace_all_test),
        cmocka_unit_test(url_parse_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
