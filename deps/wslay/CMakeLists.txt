include_directories("${CMAKE_CURRENT_LIST_DIR}/include")

include(CheckIncludeFile)
include(TestBigEndian)
check_include_file("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_file("netinet/in.h" HAVE_NETINET_IN_H)
check_include_file("winsock2.h" HAVE_WINSOCK2_H)
test_big_endian(WORDS_BIGENDIAN)
add_definitions(-DHAVE_CONFIG_H)
add_definitions(-DWSLAY_VERSION)

configure_file(
    "${CMAKE_CURRENT_LIST_DIR}/include/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/include/config.h"
    @ONLY
)

set(WSLAY_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/src")
set(WSLAY_SRC
    "${WSLAY_SRC_DIR}/wslay_event.c"
    "${WSLAY_SRC_DIR}/wslay_frame.c"
    "${WSLAY_SRC_DIR}/wslay_net.c"
    "${WSLAY_SRC_DIR}/wslay_queue.c"
    "${WSLAY_SRC_DIR}/wslay_stack.c"
)
