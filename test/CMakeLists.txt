include(cmocka.cmake)

enable_testing()

include_directories(include)
include_directories(${CMOCKA_INCLUDE_DIR} include)

find_program(MEMORYCHECK_COMMAND valgrind)
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full --error-exitcode=1")
set(memcheck_command "${MEMORYCHECK_COMMAND} ${MEMORYCHECK_COMMAND_OPTIONS}")
separate_arguments(memcheck_command)

set(SDK_TEST_SET
    "col_map_test"
    "utils_test"
)

set(BROKER_TEST_SET
    "node_test"
)

function(add_memcheck_test name)
    add_test(${name} ${name} ${ARGN})
    if (USE_VALGRIND)
        add_test(memcheck_${name} ${memcheck_command} ./${name} ${ARGN})
    endif()
endfunction(add_memcheck_test)

foreach(name ${SDK_TEST_SET})
    add_executable(sdk_${name} sdk/${name})
    target_link_libraries(sdk_${name} sdk_dslink_c cmocka)
    add_memcheck_test(sdk_${name})
endforeach()

if (DSLINK_BUILD_BROKER)
    foreach(name ${BROKER_TEST_SET})
        add_executable(broker_${name} broker/${name})
        target_link_libraries(broker_${name} sdk_broker_c sdk_dslink_c cmocka)
        add_memcheck_test(broker_${name})
    endforeach()
endif()
