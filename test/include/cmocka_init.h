/*
 * Simple linker set wrapper to automatically build the cmocka unit tests lists
 *
 * Author: Kyle Manna <kyle[at]kylemanna[d0t]com>
 *
 * Inspiration from linkerset.h:
 * https://chromium.googlesource.com/chromiumos/third_party/adhd/+/factory-1235.B/gavd/linkerset.h
 * https://gist.github.com/96a5905a42afeaee92f1
 */
#pragma once

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

/*
 * Usage: TEST(name) { ... }
 */
#define TEST(n) void n(void** state); \
        struct CMUnitTest test_##n \
        __attribute__((section("cmocka_init"),used)) = cmocka_unit_test(n); \
        void n(void** state)

#define assert_function_success(a) \
    assert_int_equal((const int)(a), 0)

//
//#define malloc(size) _test_malloc(size, __FILE__, __LINE__)
//#define calloc(num, size) _test_calloc(num, size, __FILE__, __LINE__)
//#define free(ptr) _test_free(ptr, __FILE__, __LINE__)
//
//#define dslink_malloc(size) _test_malloc(size, __FILE__, __LINE__)
//#define dslink_calloc(num, size) _test_calloc(num, size, __FILE__, __LINE__)
//#define dslink_free(ptr) _test_free(ptr, __FILE__, __LINE__)
