cmake_minimum_required(VERSION 3.0.0 FATAL_ERROR)
project(sdk_dslink_c C)

option(USE_CCACHE "Enable CCache Support" ON)
option(DSLINK_BUILD_BROKER "Whether to build the broker" ON)
option(DSLINK_BUILD_STATIC "Whether to build the static library" ON)
option(DSLINK_BUILD_EXAMPLES "Whether to build the examples" OFF)
option(DSLINK_TEST "Whether to enable tests" OFF)
option(DSLINK_PACKAGE_INCLUDES "Whether to add the includes to the resulting package" ON)
option(TOOLCHAIN_DYNAMIC_LINK_ENABLE "Enable Dynamic Linking for Toolchain" ON)

# ---------------------------------------------------------------------------------------------------
# get our OS Version String (used for directorynames)
execute_process(COMMAND ${CMAKE_CURRENT_LIST_DIR}/getos.sh --full OUTPUT_VARIABLE OSVERSION)
STRING(REGEX REPLACE "(\r?\n)+$" "" OSVERSION "${OSVERSION}")

SET(VERSION_MAJOR "1")
SET(VERSION_MINOR "5")
SET(VERSION_PATCH "0")
SET(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

add_definitions(-DIOT_DSA_C_SDK_VERSION="${VERSION}")

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
set(IOT_DSA_C_SDK_GIT_DIR "${CMAKE_CURRENT_LIST_DIR}/.git")
if (EXISTS "${IOT_DSA_C_SDK_GIT_DIR}" AND NOT "${IOT_DSA_C_SDK_GIT_COMMIT_HASH}")
    execute_process(
        COMMAND git log -1 --format=%H
        WORKING_DIRECTORY "${CMAKE_CURRENT_LIST_DIR}"
        OUTPUT_VARIABLE IOT_DSA_C_SDK_GIT_COMMIT_HASH
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    add_definitions(-DIOT_DSA_C_SDK_GIT_COMMIT_HASH="${IOT_DSA_C_SDK_GIT_COMMIT_HASH}")
    MESSAGE(STATUS "Set c-sdk git commit hash to ${IOT_DSA_C_SDK_GIT_COMMIT_HASH}")
else()
    MESSAGE(ERROR "Did not find git folder ${IOT_DSA_C_SDK_GIT_DIR}, unknown git commit hash :-(")
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

ADD_C_FLAGS("-fPIC")
IF(CMAKE_BUILD_TYPE STREQUAL "Release")
    MESSAGE(INFO "Applying secure compiler and linker flags")
    IF(${CMAKE_C_COMPILER_ID} STREQUAL "Clang")
        ADD_C_FLAGS("-Wl,-pie -fPIE -D_FORTIFY_SOURCE=2")
    ELSE()
        ADD_C_FLAGS("-pie -fPIE -D_FORTIFY_SOURCE=2")
    ENDIF()
ENDIF()

##### This are the libuv, mbed, jansson, wslay and argtable3 build files
include("${CMAKE_CURRENT_LIST_DIR}/deps/CMakeLists.txt")
include("${CMAKE_CURRENT_LIST_DIR}/deps/CMakeLists_jansson.txt")
include("${CMAKE_CURRENT_LIST_DIR}/deps/CMakeLists_wslay.txt")
include("${CMAKE_CURRENT_LIST_DIR}/deps/CMakeLists_argtable3.txt")

include(ExternalProject)

##### Configure Flags #####

ADD_C_FLAGS("-std=gnu99")
ADD_C_FLAGS("-Wno-tautological-compare")

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

# string(TOUPPER "${CMAKE_BUILD_TYPE}" DSLINK_BUILD_TYPE)
# if (DSLINK_BUILD_TYPE STREQUAL DEBUG AND NOT USE_VALGRIND)
#     ADD_C_FLAGS("-fsanitize=address")
#     ADD_C_FLAGS("-fstack-protector-all")
#  endif()

##### Configure Sources #####

include_directories("${CMAKE_CURRENT_BINARY_DIR}/include")
include_directories("${JANSSON_DIR}/include")
include_directories("${CMAKE_CURRENT_LIST_DIR}/sdk/include")

set(DSLINK_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/sdk/src")
set(DSLINK_SRC
    "${DSLINK_SRC_DIR}/col/list.c"
    "${DSLINK_SRC_DIR}/col/listener.c"
    "${DSLINK_SRC_DIR}/col/map.c"
    "${DSLINK_SRC_DIR}/col/ringbuffer.c"
    "${DSLINK_SRC_DIR}/col/vector.c"

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
    "${BROKER_SRC_DIR}/sys/throughput.c"
    "${BROKER_SRC_DIR}/sys/inspect.c"
)

###### Configure Libraries #####

set(CMAKE_MACOSX_RPATH 1)

if(NOT APPLE AND UNIX)
    set(DSLINK_PLATFORM_LIBS dl)
endif()

if (DSLINK_BUILD_STATIC OR DSLINK_BUILD_EXAMPLES)
    add_library(sdk_dslink_c-static STATIC ${LIBRARY_SRC})
    target_link_libraries(sdk_dslink_c-static jansson libuv ${DSLINK_PLATFORM_LIBS})
    set(DSLINK_INSTALL_TARGETS sdk_dslink_c sdk_dslink_c-static)
else()
    set(DSLINK_INSTALL_TARGETS sdk_dslink_c)
endif()

add_library(sdk_dslink_c SHARED ${LIBRARY_SRC})
target_link_libraries(sdk_dslink_c jansson libuv ${DSLINK_PLATFORM_LIBS})
set_target_properties(sdk_dslink_c PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR} )

set(DSLINK_INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set(DSLINK_INSTALL_BIN_DIR bin CACHE PATH "Installation directory for executables")
if (DSLINK_PACKAGE_INCLUDES)
    set(DSLINK_INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for header files")
endif()

export(TARGETS sdk_dslink_c
        FILE "${PROJECT_BINARY_DIR}/sdk_dslink_c-targets.cmake")
export(PACKAGE sdk_dslink_c)

install(TARGETS ${DSLINK_INSTALL_TARGETS}
        EXPORT sdk_dslink_c-targets
        LIBRARY DESTINATION "${DSLINK_INSTALL_LIB_DIR}" COMPONENT lib
        ARCHIVE DESTINATION "${DSLINK_INSTALL_LIB_DIR}" COMPONENT lib
        RUNTIME DESTINATION "${DSLINK_INSTALL_BIN_DIR}" COMPONENT lib)

if (DSLINK_PACKAGE_INCLUDES)
    install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/sdk/include/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev FILES_MATCHING PATTERN "*.h")
    install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/deps/mbedtls/include/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev FILES_MATCHING PATTERN "*.h")
    install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/deps/wslay/lib/includes/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev FILES_MATCHING PATTERN "*.h")
    install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/deps/wslay/lib/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev FILES_MATCHING PATTERN "*.h")
    install(DIRECTORY "${CMAKE_CURRENT_LIST_DIR}/deps/jansson/src/" DESTINATION "${DSLINK_INSTALL_INCLUDE_DIR}" COMPONENT dev FILES_MATCHING PATTERN "*.h")
endif()

####### Configure Broker #######

if (DSLINK_BUILD_BROKER)
    MESSAGE(INFO "Configured for broker build")
    include_directories("${CMAKE_CURRENT_LIST_DIR}/broker/include")

    add_library(sdk_broker_c SHARED ${BROKER_SRC})
    target_link_libraries(sdk_broker_c sdk_dslink_c)
    target_include_directories(sdk_broker_c PUBLIC "broker/include")
    set_target_properties(sdk_broker_c PROPERTIES VERSION ${VERSION} SOVERSION ${VERSION_MAJOR} )

    add_executable(broker "${BROKER_SRC_DIR}/main.c")
    target_link_libraries(broker sdk_broker_c)

    install(TARGETS broker
        RUNTIME DESTINATION "${DSLINK_INSTALL_BIN_DIR}" COMPONENT bin)
    install(TARGETS sdk_broker_c
        LIBRARY DESTINATION "${DSLINK_INSTALL_LIB_DIR}" COMPONENT bin)
endif()

###### Configure Tests #####

if (DSLINK_TEST)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/test)
    enable_testing()
endif()


###### Configure Examples ######

if (DSLINK_BUILD_EXAMPLES)
    foreach(example "responder" "requester" "storage")
        include("${CMAKE_CURRENT_LIST_DIR}/examples/${example}/CMakeLists.txt")
        add_executable(${example} ${EXAMPLE_SRC})
        target_link_libraries(${example} sdk_dslink_c-static)
    endforeach()
endif()

# ---------------------------------------------------------------------------------------------------
# package definition
SET(CPACK_CMAKE_GENERATOR "Unix Makefiles")
SET(CPACK_PACKAGE_CONTACT "https://mycase.cloudapps.cisco.com/case")
SET(CPACK_PACKAGE_URL "http://www.cisco.com")
SET(CPACK_PACKAGE_LICENSE "Apache License, Version 2.0")
SET(CPACK_PACKAGE_RELOCATABLE "false")
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "C DSLink SDK")
SET(CPACK_PACKAGE_DESCRIPTION "C DSLink SDK")
SET(CPACK_PACKAGE_RELOCATABLE "false")
SET(CPACK_PACKAGE_VENDOR "Cisco Kinetic EFM")
SET(CPACK_PACKAGE_NAME "sdk-dslink-c")
SET(CPACK_PACKAGE_VERSION "${VERSION}")
SET(CPACK_PACKAGE_VERSION_MAJOR "${VERSION_MAJOR}")
SET(CPACK_PACKAGE_VERSION_MINOR "${VERSION_MINOR}")
SET(CPACK_PACKAGE_VERSION_PATCH "${VERSION_PATCH}")
SET(CPACK_PACKAGE_INSTALL_DIRECTORY "sdk-dslink-c")
SET(CPACK_PACKAGE_DEFAULT_LOCATION "/")
SET(CPACK_COMPONENTS_ALL bin lib dev)
set(CPACK_COMPONENT_BIN_DEPENDS lib)
set(CPACK_COMPONENT_DEV_DEPENDS lib)
SET(CPACK_INSTALL_CMAKE_PROJECTS "${CMAKE_BINARY_DIR};${CMAKE_PROJECT_NAME};ALL;/")
SET(PACKAGING_REPLACES "")
SET(PACKAGING_CONFLICTS "")

# some general seetings for the packaging process
set(CPACK_DEB_COMPONENT_INSTALL ON)
SET(CPACK_COMPONENTS_ALL_SET_BY_USER "TRUE")
SET(CPACK_COMPONENTS_GROUPING "IGNORE")
SET(CPACK_COMPONENT_UNSPECIFIED_HIDDEN "TRUE")
SET(CPACK_COMPONENT_UNSPECIFIED_REQUIRED "TRUE")
SET(CPACK_SET_DESTDIR "OFF")

if((${OSVERSION} STREQUAL "Debian8") OR
   (${OSVERSION} STREQUAL "Ubuntu16.04"))

  # Debian/Ubuntu
  SET(CPACK_GENERATOR "DEB")
  SET(CPACK_DEBIAN_PACKAGE_ARCHITECTURE "amd64")
  SET(CPACK_DEBIAN_PACKAGE_SECTION "Network")
  SET(CPACK_PACKAGE_FILE_NAME "sdk-dslink-c_${VERSION}_amd64")
  SET(CPACK_DEBIAN_PACKAGE_REQUIRES "")
  SET(CPACK_DEBIAN_PACKAGE_SUGGESTS "")

elseif((${OSVERSION} STREQUAL "CentOS7") OR
       (${OSVERSION} STREQUAL "RHEL7"))

  SET(CPACK_GENERATOR "RPM")
  SET(CPACK_RPM_PACKAGE_ARCHITECTURE "x86_64")
  SET(CPACK_RPM_PACKAGE_GROUP "Applications/Networking")
  SET(CPACK_PACKAGE_FILE_NAME "sdk-dslink-c-${VERSION}.el7.x86_64")
  SET(CPACK_RPM_PACKAGE_REQUIRES "")
  SET(CPACK_RPM_PACKAGE_SUGGESTS "")
  SET(CPACK_RPM_COMPONENT_INSTALL ON)

else()
    message(WARNING "OS unknown for packaging")
endif()

INCLUDE(CPack)

