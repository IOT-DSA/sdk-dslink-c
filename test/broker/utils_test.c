#include "cmocka_init.h"

#include <broker/utils.h>

static
void setHostFrom_test(void** state)
{
  (void) state;

  assert_string_equal(setHostFrom("http", "localhost", "12345"), "http://localhost:12345/conn" );
  assert_string_equal(setHostFrom("http", "anyhost.de", "12345"), "http://anyhost.de:12345/conn" );
  assert_string_equal(setHostFrom("http", "1.2.3.4", "12345"), "http://1.2.3.4:12345/conn" );
  assert_string_equal(setHostFrom("http", "0:1:2:3:4:5:6:7", "8888"), "http://[0:1:2:3:4:5:6:7]:8888/conn" );
  assert_string_equal(setHostFrom("http", "0:1:2::7:8", "8888"), "http://[0:1:2::7:8]:8888/conn" );

  // Special case IPv4 unspecified address
  assert_string_equal(setHostFrom("http", "0.0.0.0", "12345"), "http://127.0.0.1:12345/conn" );

  // Special case IPv6 unspecified address
  assert_string_equal(setHostFrom("http", "::/0", "12345"), "http://[::1]:12345/conn" );
  assert_string_equal(setHostFrom("http", "::/128", "23456"), "http://[::1]:23456/conn" );
  assert_string_equal(setHostFrom("http", "::1", "1234"), "http://[::1]:1234/conn" );
  assert_string_equal(setHostFrom("http", "0:0:0::0", "12345"), "http://[::1]:12345/conn" );
  assert_string_equal(setHostFrom("http", "0:0::0:0", "12345"), "http://[::1]:12345/conn" );
  assert_string_equal(setHostFrom("http", "0:0:0:0:0:0:0:0", "12345"), "http://[::1]:12345/conn" );


}


int main() {
    const struct CMUnitTest tests[] = {
      cmocka_unit_test(setHostFrom_test)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
