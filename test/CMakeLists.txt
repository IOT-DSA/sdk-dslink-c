if (DSLINK_TEST)
  include(cmocka.cmake)

  enable_testing()

  include_directories(include)
  include_directories(${CMOCKA_INCLUDE_DIR} include)

  find_program(MEMORYCHECK_COMMAND valgrind)
  set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full")

  function(add_memcheck_test name binary)
      set(memcheck_command "${CMAKE_MEMORYCHECK_COMMAND} ${CMAKE_MEMORYCHECK_COMMAND_OPTIONS}")
      separate_arguments(memcheck_command)
      add_test(${name} ${binary} ${ARGN})
      add_test(memcheck_${name} ${memcheck_command} ./${binary} ${ARGN})
  endfunction(add_memcheck_test)

  foreach(tname "col_map")
      add_executable(${tname}_test src/${tname}_test.c)
      target_link_libraries(${tname}_test sdk_dslink_c cmocka)
      add_dependencies(${tname}_test ${tname}_test sdk_dslink_c cmocka)
      add_memcheck_test(${tname}_test ${tname}_test)
  endforeach()

endif()
