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
cmake -DDSLINK_TEST=ON ${CMAKE_FLAGS} ..
make
make test
