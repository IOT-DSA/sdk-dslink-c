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
cmake -DDSLINK_BUILD_EXAMPLES=ON -DDSLINK_BUILD_BROKER=ON -DCMAKE_BUILD_TYPE=Release -DDSLINK_TEST=ON ..

if [ -f Makefile ]
then
  make "${@}"
else
  ninja "${@}"
fi

