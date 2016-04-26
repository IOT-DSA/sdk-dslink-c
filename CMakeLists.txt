cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
project(sdk_dslink_c C)

option(USE_CCACHE "Enable CCache Support" ON)
option(DSLINK_BUILD_BROKER "Whether to build the broker" OFF)
option(DSLINK_BUILD_EXAMPLES "Whether to build the examples" OFF)
option(DSLINK_TEST "Whether to enable tests" OFF)
option(TOOLCHAIN_DYNAMIC_LINK_ENABLE "Enable Dynamic Linking for Toolchain" ON)

##### Configure CMake Modules #####

set(CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/tools/cmake)

include(MacroEnsureOutOfSourceBuild)
ensure_out_of_source_build("Please do not build the C SDK inside the source directory.")

##### Check Configuration #####

if ("${CMAKE_GENERATOR}" STREQUAL "Ninja" AND DSLINK_TEST)
    message(WARNING "C SDK Unit Tests are currently not supported under Ninja.")
    set(DSLINK_TEST OFF)
endif()

##### Define Macros #####

macro(ADD_C_FLAGS flags)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${flags}")
endmacro()

##### Git Version Info ####

set(GIT_DIR "${CMAKE_SOURCE_DIR}/.git")
if (EXISTS "${GIT_DIR}" AND IS_DIRECTORY "${GIT_DIR}" AND NOT "${GIT_COMMIT_HASH}")
    execute_process(
        COMMAND git log -1 --format=%H
        WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
        OUTPUT_VARIABLE GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
endif()

##### Toolchain Configuration #####

ADD_C_FLAGS("${TOOLCHAIN_C_FLAGS}")

if (NOT TOOLCHAIN_DYNAMIC_LINK_ENABLE)
    set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS)
    set(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS)
endif()

##### Configure CCache Support ####

find_program(CCACHE_FOUND ccache)
if (CCACHE_FOUND AND USE_CCACHE)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_COMPILE ccache)
    set_property(GLOBAL PROPERTY RULE_LAUNCH_LINK ccache)
endif()

##### Configure Dependencies #####

foreach(dep "mbed" "wslay" "argtable3" "jansson" "libuv")
    include("${CMAKE_CURRENT_LIST_DIR}/deps/${dep}/CMakeLists.txt")
endforeach()

include(ExternalProject)
ADD_C_FLAGS("-fPIC")

##### Configure Flags #####

ADD_C_FLAGS("-std=gnu99")

if (NOT NO_WARNINGS)
    ADD_C_FLAGS("-Wall -Wextra -Werror")
    ADD_C_FLAGS("-Wno-overlength-strings")
    ADD_C_FLAGS("-pedantic")
endif()

if (${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
    ADD_C_FLAGS("-Qunused-arguments")
endif()

if (${CMAKE_SYSTEM_NAME} STREQUAL "Linux")
    ADD_C_FLAGS("-pthread")
endif()

string(TOUPPER "${CMAKE_BUILD_TYPE}" DSLINK_BUILD_TYPE)
if (DSLINK_BUILD_TYPE STREQUAL DEBUG AND NOT USE_VALGRIND)
    ADD_C_FLAGS("-fsanitize=address")
    ADD_C_FLAGS("-fstack-protector-all")
endif()

##### Configure Sources #####

include_directories("${CMAKE_CURRENT_BINARY_DIR}/include")
include_directories("${JANSSON_DIR}/include")
include_directories("${CMAKE_CURRENT_LIST_DIR}/sdk/include")

set(DSLINK_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/sdk/src")
set(DSLINK_SRC
    "${DSLINK_SRC_DIR}/col/list.c"
    "${DSLINK_SRC_DIR}/col/listener.c"
    "${DSLINK_SRC_DIR}/col/map.c"

    "${DSLINK_SRC_DIR}/mem/mem.c"
    "${DSLINK_SRC_DIR}/mem/ref.c"

    "${DSLINK_SRC_DIR}/storage/storage.c"
    "${DSLINK_SRC_DIR}/storage/json_file.c"

    "${DSLINK_SRC_DIR}/msg/list_response.c"
    "${DSLINK_SRC_DIR}/msg/request_handler.c"
    "${DSLINK_SRC_DIR}/msg/response_handler.c"
    "${DSLINK_SRC_DIR}/msg/sub_response.c"

    "${DSLINK_SRC_DIR}/base64_url.c"
    "${DSLINK_SRC_DIR}/dslink.c"
    "${DSLINK_SRC_DIR}/handshake.c"
    "${DSLINK_SRC_DIR}/log.c"
    "${DSLINK_SRC_DIR}/node.c"
    "${DSLINK_SRC_DIR}/socket.c"
    "${DSLINK_SRC_DIR}/url.c"
    "${DSLINK_SRC_DIR}/utils.c"
    "${DSLINK_SRC_DIR}/ws.c"
    "${DSLINK_SRC_DIR}/requester.c"
)

set(LIBRARY_SRC
    "${ARGTABLE_SRC}"
    "${DSLINK_SRC}"
    "${MBED_SRC}"
    "${WSLAY_SRC}"
)

set(BROKER_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/broker/src")
set(BROKER_SRC
    "${BROKER_SRC_DIR}/data/data.c"
    "${BROKER_SRC_DIR}/data/data_actions.c"

    "${BROKER_SRC_DIR}/sys/sys.c"
    "${BROKER_SRC_DIR}/query/query.c"

    "${BROKER_SRC_DIR}/msg/msg_handler.c"
    "${BROKER_SRC_DIR}/msg/msg_close.c"
    "${BROKER_SRC_DIR}/msg/msg_invoke.c"
    "${BROKER_SRC_DIR}/msg/msg_list.c"
    "${BROKER_SRC_DIR}/msg/msg_list_remote.c"
    "${BROKER_SRC_DIR}/msg/msg_set.c"
    "${BROKER_SRC_DIR}/msg/msg_subscribe.c"
    "${BROKER_SRC_DIR}/msg/msg_unsubscribe.c"

    "${BROKER_SRC_DIR}/net/http.c"
    "${BROKER_SRC_DIR}/net/server.c"
    "${BROKER_SRC_DIR}/net/ws.c"
    "${BROKER_SRC_DIR}/net/ws_handler.c"

    "${BROKER_SRC_DIR}/broker.c"
    "${BROKER_SRC_DIR}/config.c"
    "${BROKER_SRC_DIR}/handshake.c"
    "${BROKER_SRC_DIR}/node/node.c"
    "${BROKER_SRC_DIR}/remote_dslink.c"
    "${BROKER_SRC_DIR}/stream.c"
    "${BROKER_SRC_DIR}/utils.c"
    "${BROKER_SRC_DIR}/sys/token.c"
    "${BROKER_SRC_DIR}/sys/trace.c"
    "${BROKER_SRC_DIR}/upstream/upstream_sys_node.c"
    "${BROKER_SRC_DIR}/sys/restart.c"
    "${BROKER_SRC_DIR}/upstream/upstream_node.c"
    "${BROKER_SRC_DIR}/permission/permission.c"
    "${BROKER_SRC_DIR}/sys/clear_conns.c"
    "${BROKER_SRC_DIR}/upstream/upstream_handshake.c"
    "${BROKER_SRC_DIR}/upstream/async_connect.c"
    "${BROKER_SRC_DIR}/node/node_serialization.c"
    "${BROKER_SRC_DIR}/sys/permission_action.c"
    "${BROKER_SRC_DIR}/msg/sub_stream.c"
    "${BROKER_SRC_DIR}/subscription.c"
    "${BROKER_SRC_DIR}/node/virtual_downstream.c"
    "${BROKER_SRC_DIR}/msg/msg_remove.c"
)
###### Configure Tests #####

if (DSLINK_TEST)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/test)
    enable_testing()
endif()

###### Configure Libraries #####

set(CMAKE_MACOSX_RPATH 1)
add_library(sdk_dslink_c-object OBJECT ${LIBRARY_SRC})

add_library(sdk_dslink_c-static STATIC $<TARGET_OBJECTS:sdk_dslink_c-object>)
target_link_libraries(sdk_dslink_c-static jansson libuv)

add_library(sdk_dslink_c SHARED $<TARGET_OBJECTS:sdk_dslink_c-object>)
target_link_libraries(sdk_dslink_c jansson libuv)

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
install(DIRECTORY "deps/mbed/include/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev)
install(DIRECTORY "deps/wslay/include/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev)
install(DIRECTORY "deps/jansson/include/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev)

####### Configure Broker #######

if (DSLINK_BUILD_BROKER)
    install(DIRECTORY "broker/include/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev)

    if (GIT_COMMIT_HASH)
        set_source_files_properties(
            "broker/src/broker.c"
            PROPERTIES
            COMPILE_DEFINITIONS GIT_COMMIT_HASH="${GIT_COMMIT_HASH}"
        )
    endif()

    add_library(sdk_broker_c-object OBJECT ${BROKER_SRC})
    target_include_directories(sdk_broker_c-object PUBLIC "broker/include")

    add_library(sdk_broker_c SHARED $<TARGET_OBJECTS:sdk_broker_c-object>)
    target_link_libraries(sdk_broker_c sdk_dslink_c)
    target_include_directories(sdk_broker_c PUBLIC "broker/include")

    add_library(sdk_broker_c-static STATIC $<TARGET_OBJECTS:sdk_broker_c-object>)
    target_link_libraries(sdk_broker_c-static sdk_dslink_c-static)
    target_include_directories(sdk_broker_c-static PUBLIC "broker/include")

    add_executable(broker "${BROKER_SRC_DIR}/main.c")
    target_link_libraries(broker sdk_broker_c-static)
endif()

###### Configure Examples ######

if (DSLINK_BUILD_EXAMPLES)
    foreach(example "responder" "requester" "storage")
        include("${CMAKE_CURRENT_SOURCE_DIR}/examples/${example}/CMakeLists.txt")
        add_executable(${example} ${EXAMPLE_SRC})
        target_link_libraries(${example} sdk_dslink_c-static)
    endforeach()
endif()
