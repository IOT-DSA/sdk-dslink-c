#
# Unit Test Framework cmocka
#
# Copyright (c) 2015 Kyle Manna <kyle[at]kylemanna[dot]com>
#

# Enable ExternalProject CMake module
include(ExternalProject)

ExternalProject_Add(cmocka_ep
        GIT_REPOSITORY git://git.cryptomilk.org/projects/cmocka.git
        GIT_TAG cmocka-1.0.1
        # Use git submodule to fetch source manually and in-tree, store in SOURCE_DIR
        SOURCE_DIR ${CMAKE_SOURCE_DIR}/modules/cmocka
        CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
        -DWITH_STATIC_LIB=ON
        -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG:PATH=Debug
        -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE:PATH=Release
        -DCMAKE_C_ARGS=-Wno-format

        # Don't build unused examples and disable install step
        BUILD_COMMAND $(MAKE) cmocka_static
        INSTALL_COMMAND "")

add_library(cmocka STATIC IMPORTED GLOBAL)
ExternalProject_Get_Property(cmocka_ep binary_dir)

set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION
        "${binary_dir}/src/libcmocka.a")
set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION_DEBUG
        "${binary_dir}/src/Debug/libcmocka.a")
set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION_RELEASE
        "${binary_dir}/src/Release/libcmocka.a")

add_dependencies(cmocka cmocka_ep)

ExternalProject_Get_Property(cmocka_ep source_dir)
set(CMOCKA_INCLUDE_DIR ${source_dir}/include GLOBAL)
