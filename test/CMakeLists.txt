include(cmocka.cmake)

enable_testing()

include_directories(include)
include_directories(${CMOCKA_INCLUDE_DIR} include)

find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full --error-exitcode=1")

function(add_memcheck_test name)
    set(memcheck_command "${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS}")
    separate_arguments(memcheck_command)
    add_test(${name} ${name} ${ARGN})
    add_test(memcheck_${name} ${memcheck_command} ./${name} ${ARGN})
endfunction(add_memcheck_test)

foreach(tname "col_map")
    add_executable(${tname}_test sdk/${tname}_test.c)
    target_link_libraries(${tname}_test sdk_dslink_c cmocka ${JANSSON_LIB})
    add_memcheck_test(${tname}_test)
endforeach()
