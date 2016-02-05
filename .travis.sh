#!/usr/bin/env bash
set -e

if [ "${BUILD_ARCH}" == "arm" ]
then
  echo "ARM builds are not supported yet."
  exit 1
fi

rm -rf build
mkdir -p build
cd build

if [ "${TRAVIS_OS_NAME}" != "osx" ]; then
    VALGRIND="-DUSE_VALGRIND=ON"
fi
cmake -DDSLINK_TEST=ON -DDSLINK_BUILD_BROKER=ON "$VALGRIND" ${CMAKE_FLAGS} ..
make
make test
