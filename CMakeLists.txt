cmake_minimum_required(VERSION 2.8)
project(sdk_dslink_c C)

option(DSLINK_BUILD_BROKER "Whether to build the broker" OFF)
option(DSLINK_BUILD_EXAMPLES "Whether to build the examples" OFF)
option(DSLINK_TEST "Whether to enable tests" ON)

option(DSLINK_JANSSON_SYSTEM
    "Whether to use system Jansson library or manually build it"
    OFF
)

######## Define Macros #######

macro(ADD_C_FLAGS flags)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flags}")
endmacro()

##### Configure Dependencies #####

foreach(dep "mbed" "wslay" "argtable3")
    include("${CMAKE_CURRENT_SOURCE_DIR}/deps/${dep}/CMakeLists.txt")
endforeach()

include(ExternalProject)
ADD_C_FLAGS("-fPIC")

if (NOT DSLINK_JANSSON_SYSTEM)
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
    set(JANSSON_LIB "${JANSSON_DIR}/lib/libjansson.a")
else()
    set(JANSSON_LIB "jansson")
endif()

##### Configure Flags #####

ADD_C_FLAGS("-std=gnu99")
ADD_C_FLAGS("-Wall -Wextra -Werror")
ADD_C_FLAGS("-Wno-overlength-strings")
ADD_C_FLAGS("-pedantic")

string(TOUPPER "${CMAKE_BUILD_TYPE}" DSLINK_BUILD_TYPE)
if (DSLINK_BUILD_TYPE STREQUAL DEBUG AND NOT USE_VALGRIND)
    ADD_C_FLAGS("-fsanitize=address")
    ADD_C_FLAGS("-fstack-protector-all")
endif()

##### Configure Sources #####

include_directories("${CMAKE_CURRENT_BINARY_DIR}/include")
include_directories("${JANSSON_DIR}/include")
include_directories("sdk/include")

set(DSLINK_SRC_DIR "sdk/src")
set(DSLINK_SRC
    "${DSLINK_SRC_DIR}/col/list.c"
    "${DSLINK_SRC_DIR}/col/listener.c"
    "${DSLINK_SRC_DIR}/col/map.c"

    "${DSLINK_SRC_DIR}/mem/mem.c"
    "${DSLINK_SRC_DIR}/mem/ref.c"

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

set(BROKER_SRC_DIR "broker/src")
set(BROKER_SRC
    "${BROKER_SRC_DIR}/data/data.c"
    "${BROKER_SRC_DIR}/data/data_actions.c"

    "${BROKER_SRC_DIR}/sys/sys.c"
    "${BROKER_SRC_DIR}/query/query.c"

    "${BROKER_SRC_DIR}/msg/msg_handler.c"
    "${BROKER_SRC_DIR}/msg/msg_invoke.c"
    "${BROKER_SRC_DIR}/msg/msg_list.c"
    "${BROKER_SRC_DIR}/msg/msg_list_remote.c"
    "${BROKER_SRC_DIR}/msg/msg_subscribe.c"

    "${BROKER_SRC_DIR}/net/http.c"
    "${BROKER_SRC_DIR}/net/server.c"
    "${BROKER_SRC_DIR}/net/ws.c"

    "${BROKER_SRC_DIR}/broker.c"
    "${BROKER_SRC_DIR}/config.c"
    "${BROKER_SRC_DIR}/handshake.c"
    "${BROKER_SRC_DIR}/main.c"
    "${BROKER_SRC_DIR}/node.c"
    "${BROKER_SRC_DIR}/remote_dslink.c"
    "${BROKER_SRC_DIR}/stream.c"
)

set(EXAMPLE_RESPONDER_SRC_DIR "examples/responder/src")
set(EXAMPLE_RESPONDER_SRC
    "${EXAMPLE_RESPONDER_SRC_DIR}/main.c"
)

###### Configure Tests #####

if (DSLINK_TEST)
    add_subdirectory(test)
    enable_testing()
endif()

###### Configure Libraries #####

set(CMAKE_MACOSX_RPATH 1)
add_library(sdk_dslink_c-object OBJECT ${LIBRARY_SRC})

add_library(sdk_dslink_c-static STATIC $<TARGET_OBJECTS:sdk_dslink_c-object>)
target_link_libraries(sdk_dslink_c-static ${JANSSON_LIB})

add_library(sdk_dslink_c SHARED $<TARGET_OBJECTS:sdk_dslink_c-object>)
target_link_libraries(sdk_dslink_c ${JANSSON_LIB})

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

####### Configure Broker #######

if (DSLINK_BUILD_BROKER)
    add_executable(broker "${BROKER_SRC}")
    target_link_libraries(broker sdk_dslink_c)
    target_include_directories(broker PRIVATE "broker/include")
endif()

###### Configure Examples ######

if (DSLINK_BUILD_EXAMPLES)
    foreach(example "responder")
        include("${CMAKE_CURRENT_SOURCE_DIR}/examples/${example}/CMakeLists.txt")
        add_executable(${example} ${EXAMPLE_SRC})
        target_link_libraries(${example} sdk_dslink_c)
    endforeach()
endif()
