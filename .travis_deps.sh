#!/usr/bin/env bash
if [ "${TRAVIS_OS_NAME}" == "osx" ]
then
  brew update
  brew install jansson
else
  sudo add-apt-repository ppa:ubuntu-toolchain-r/test -y
  sudo add-apt-repository ppa:george-edison55/cmake-3.x -y
  sudo apt-get update
  sudo apt-get install -qq -y \
    gcc-4.8 \
    gcc-4.9 \
    gcc-5 \
    cmake \
    libjansson-dev \
    libjansson4 \
    valgrind
  if [ "${BUILD_ARCH}" == "arm" ]
  then
    sudo apt-get instal -qq -y
      debootstrap \
      qemu-user-static \
      binfmt-support \
      sbuild
  fi
fi
