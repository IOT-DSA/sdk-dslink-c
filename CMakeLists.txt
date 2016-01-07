cmake_minimum_required(VERSION 2.8)
project(sdk_dslink_c C)

######## Configure Options #######

option(DSLINK_BUILD_EXAMPLES "Whether to build the examples" OFF)

##### Configure Dependencies #####

foreach(dep "mbed" "wslay" "argtable3")
    include("${CMAKE_CURRENT_SOURCE_DIR}/deps/${dep}/CMakeLists.txt")
endforeach()

include(ExternalProject)

ExternalProject_Add(JANSSON
    PREFIX jansson
    GIT_REPOSITORY "https://github.com/akheron/jansson.git"
    GIT_TAG "e44b223"
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
                -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
                -DCMAKE_C_FLAGS=${CMAKE_C_FLAGS}
                -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/jansson
                -DJANSSON_BUILD_DOCS=OFF
                -DJANSSON_EXAMPLES=OFF
                -DJANSSON_WITHOUT_TESTS=ON
)
set(JANSSON_DIR "${CMAKE_CURRENT_BINARY_DIR}/jansson")

##### Configure Flags #####

macro(ADD_C_FLAGS flags)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flags}")
endmacro()

ADD_C_FLAGS("-std=gnu99")
ADD_C_FLAGS("-Wall -Wextra -Werror")
ADD_C_FLAGS("-Wno-overlength-strings")
ADD_C_FLAGS("-pedantic -fPIC")

##### Configure Sources #####

include_directories("${CMAKE_CURRENT_BINARY_DIR}/include")
include_directories("${JANSSON_DIR}/include")
include_directories("sdk/include")

set(DSLINK_SRC_DIR "sdk/src")
set(DSLINK_SRC
    "${DSLINK_SRC_DIR}/col/list.c"
    "${DSLINK_SRC_DIR}/col/map.c"

    "${DSLINK_SRC_DIR}/msg/list_response.c"
    "${DSLINK_SRC_DIR}/msg/request_handler.c"
    "${DSLINK_SRC_DIR}/msg/sub_response.c"

    "${DSLINK_SRC_DIR}/base64_url.c"
    "${DSLINK_SRC_DIR}/dslink.c"
    "${DSLINK_SRC_DIR}/event_loop.c"
    "${DSLINK_SRC_DIR}/handshake.c"
    "${DSLINK_SRC_DIR}/log.c"
    "${DSLINK_SRC_DIR}/node.c"
    "${DSLINK_SRC_DIR}/socket.c"
    "${DSLINK_SRC_DIR}/url.c"
    "${DSLINK_SRC_DIR}/utils.c"
    "${DSLINK_SRC_DIR}/ws.c"
)

set(LIBRARY_SRC
    "${ARGTABLE_SRC}"
    "${DSLINK_SRC}"
    "${MBED_SRC}"
    "${WSLAY_SRC}"
)

set(EXAMPLE_RESPONDER_SRC_DIR "examples/responder/src")
set(EXAMPLE_RESPONDER_SRC
    "${EXAMPLE_RESPONDER_SRC_DIR}/main.c"
)

###### Configure Libraries #####

set(CMAKE_MACOSX_RPATH 1)
link_directories("${JANSSON_DIR}/lib")
add_library(sdk_dslink_c-object OBJECT ${LIBRARY_SRC})

add_library(sdk_dslink_c-static STATIC $<TARGET_OBJECTS:sdk_dslink_c-object>)
target_link_libraries(sdk_dslink_c-static jansson)

add_library(sdk_dslink_c SHARED $<TARGET_OBJECTS:sdk_dslink_c-object>)
target_link_libraries(sdk_dslink_c jansson)

set(DSLINK_INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(DSLINK_INSTALL_BIN_DIR bin CACHE PATH "Installation directory for executables")
set(DSLINK_INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for header files")

export(TARGETS sdk_dslink_c
        FILE "${PROJECT_BINARY_DIR}/sdk_dslink_c-targets.cmake")
export(PACKAGE sdk_dslink_c)

install(TARGETS sdk_dslink_c
        EXPORT sdk_dslink_c-targets
        LIBRARY DESTINATION "${DSLINK_INSTALL_LIB_DIR}" COMPONENT lib
        ARCHIVE DESTINATION "${DSLINK_INSTALL_LIB_DIR}" COMPONENT lib
        RUNTIME DESTINATION "${DSLINK_INSTALL_BIN_DIR}" COMPONENT lib)

install(DIRECTORY "sdk/include/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev)

###### Configure Examples ######

if (DSLINK_BUILD_EXAMPLES)
    foreach(example "responder")
        include("${CMAKE_CURRENT_SOURCE_DIR}/examples/${example}/CMakeLists.txt")
        add_executable(${example} ${EXAMPLE_SRC})
        target_link_libraries(${example} sdk_dslink_c)
    endforeach()
endif()
