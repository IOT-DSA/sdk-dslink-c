#!/usr/bin/env bash
set -e

DEFAULT_ARGS="-DDSLINK_BUILD_EXAMPLES=ON -DDSLINK_BUILD_BROKER=ON -DCMAKE_BUILD_TYPE=Release"

if [[ -z "${DSA_CMAKE_ARGS}" ]]
then
  DSA_CMAKE_ARGS="${DEFAULT_ARGS}"

  if [[ "${CMAKE_USE_NINJA}" == "true" ]]
  then
    DSA_CMAKE_ARGS="${DSA_CMAKE_ARGS} -DDSLINK_TEST=OFF"
  fi
fi

if [[ "${CMAKE_USE_NINJA}" == "true" ]]
then
  DSA_CMAKE_ARGS="${DSA_CMAKE_ARGS} -G Ninja"
fi

LOC=$(dirname $0)
cd ${LOC}/..
if [[ ! -f build/CMakeCache.txt ]]
then
  rm -rf build
  mkdir -p build
fi

cd build

cmake ${DSA_CMAKE_ARGS} ..

if [ -f Makefile ]
then
  make "${@}"
else
  ninja "${@}"
fi
