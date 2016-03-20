#!/usr/bin/env bash
set -e
LOC=$(dirname $0)
cd ${LOC}/..
if [[ ! -d build ]]
then
  rm -rf build
  mkdir -p build
fi

cd build
cmake -DDSLINK_BUILD_EXAMPLES=ON -DDSLINK_BUILD_BROKER=ON -DCMAKE_BUILD_TYPE=Debug -DDSLINK_COVERAGE=ON -DDSLINK_TEST=ON ..
make "${@}"
