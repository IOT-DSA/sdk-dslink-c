#
# Unit Test Framework cmocka
#
# Copyright (c) 2015 Kyle Manna <kyle[at]kylemanna[dot]com>
#

# Enable ExternalProject CMake module
include(ExternalProject)

ExternalProject_Add(cmocka_bundle
    URL https://git.cryptomilk.org/projects/cmocka.git/snapshot/cmocka-1.0.1.tar.gz
    URL_MD5 79b19768d7a9a7fcc119e0b393755c39
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_SYSTEM_NAME=${CMAKE_SYSTEM_NAME}
    -DWITH_STATIC_LIB=ON
    -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG:PATH=Debug
    -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE:PATH=Release
    -DCMAKE_C_FLAGS=-Wno-format-security -Wno-format
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}

    # Don't build unused examples and disable install step
    CMAKE_GENERATOR "Unix Makefiles"
    BUILD_COMMAND make cmocka_static
    INSTALL_COMMAND ""
)

add_library(cmocka STATIC IMPORTED GLOBAL)
ExternalProject_Get_Property(cmocka_bundle binary_dir)

set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION
    "${binary_dir}/src/libcmocka.a")
set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION_DEBUG
    "${binary_dir}/src/Debug/libcmocka.a")
set_property(TARGET cmocka PROPERTY IMPORTED_LOCATION_RELEASE
    "${binary_dir}/src/Release/libcmocka.a")

add_dependencies(cmocka cmocka_bundle)

ExternalProject_Get_Property(cmocka_bundle source_dir)
set(CMOCKA_INCLUDE_DIR ${source_dir}/include GLOBAL)
