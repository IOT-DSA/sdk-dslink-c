include_directories("${CMAKE_CURRENT_LIST_DIR}/include")

set(EXAMPLE_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/src")
set(EXAMPLE_SRC
    "${EXAMPLE_SRC_DIR}/main.c"
    "${EXAMPLE_SRC_DIR}/replicator.c"
    "${EXAMPLE_SRC_DIR}/rng.c"
    "${EXAMPLE_SRC_DIR}/invoke.c"
)
