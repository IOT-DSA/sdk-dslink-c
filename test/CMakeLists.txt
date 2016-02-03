include(cmocka.cmake)

enable_testing()

include_directories(include)
include_directories(${CMOCKA_INCLUDE_DIR} include)

find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full --error-exitcode=1")

set(SDK_TEST_SET
    "col_map_test"
)

function(add_memcheck_test name)
    set(memcheck_command "${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS}")
    separate_arguments(memcheck_command)
    add_test(${name} ${name} ${ARGN})
    add_test(memcheck_${name} ${memcheck_command} ./${name} ${ARGN})
endfunction(add_memcheck_test)

foreach(name ${SDK_TEST_SET})
    add_executable(sdk_${name} sdk/${name})
    target_link_libraries(sdk_${name} sdk_dslink_c cmocka ${JANSSON_LIB})
    add_memcheck_test(sdk_${name})
endforeach()
