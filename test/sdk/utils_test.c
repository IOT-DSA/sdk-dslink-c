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
    {
        const char address[] = "http://[::/128]:8100/conn";

        Url* url = dslink_url_parse(address);
        assert_non_null(url);
        assert_string_equal("::/128", url->host);
        assert_string_equal("http", url->scheme);
        assert_false(url->secure);
        assert_true(8100u == url->port);
        assert_string_equal("/conn", url->uri);
    }
}

static
void ipv6_test(void** state)
{
    (void)state;

    const char* ipv6 = "::1";
    assert_true(dslink_isipv6address(ipv6));
    ipv6 = "2001:420:44e7:1300:b039:6611:2e10:e963";
    assert_true(dslink_isipv6address(ipv6));
    ipv6 = "2001:db8::ff00:42:8329";
    assert_true(dslink_isipv6address(ipv6));
    ipv6 = "::192.0.2.128";
    assert_true(dslink_isipv6address(ipv6));
    ipv6 = "::1/128";
    assert_true(dslink_isipv6address(ipv6));

    const char* ipv4 = "127.0.0.1";
    assert_false(dslink_isipv6address(ipv4));
    ipv4 = "0.0.0.0";
    assert_false(dslink_isipv6address(ipv4));
    ipv4 = "127.0.0.1";
    assert_false(dslink_isipv6address(ipv4));
}

static
void checkIpv4Address_test(void** state)
{
    (void)state;

    const char* ipv4 = "127.0.0.1";
    const char* host = dslink_checkIpv4Address(ipv4);
    assert_string_equal("127.0.0.1", host);

    ipv4 = "0.0.0.0";
    host = dslink_checkIpv4Address(ipv4);
    assert_string_equal("127.0.0.1", host);
}

static
void checkIpv6Address_test(void** state)
{
    (void)state;

    const char* ipv6 = "2001:420:44e7:1300:b039:6611:2e10:e963";
    const char* host = dslink_checkIpv6Address(ipv6);
    assert_string_equal("2001:420:44e7:1300:b039:6611:2e10:e963", host);

    ipv6 = "::1";
    host = dslink_checkIpv6Address(ipv6);
    assert_string_equal("::1", host);

    ipv6 = "0:0:0:0:0:0:0:0";
    host = dslink_checkIpv6Address(ipv6);
    assert_string_equal("::1", host);

    ipv6 = "::/128";
    host = dslink_checkIpv6Address(ipv6);
    assert_string_equal("::1", host);

    ipv6 = "::/0";
    host = dslink_checkIpv6Address(ipv6);
    assert_string_equal("::1", host);
}

int main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(utils_str_replace_all_test),
        cmocka_unit_test(url_parse_test),
        cmocka_unit_test(ipv6_test),
        cmocka_unit_test(checkIpv4Address_test),
        cmocka_unit_test(checkIpv6Address_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
