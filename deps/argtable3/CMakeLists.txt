include_directories("${CMAKE_CURRENT_LIST_DIR}/include")

ADD_C_FLAGS("-fPIC")
set(ARGTABLE_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/src")
set(ARGTABLE_SRC
    "${ARGTABLE_SRC_DIR}/argtable3.c"
)
