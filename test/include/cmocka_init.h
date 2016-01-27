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
