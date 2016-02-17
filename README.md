# sdk-dslink-c

[![Build Status](https://travis-ci.org/IOT-DSA/sdk-dslink-c.svg?branch=feature_broker)](https://travis-ci.org/IOT-DSA/sdk-dslink-c)

C binding for the DSA API.

This binding is currently under heavy development. This means APIs can change at any time
and is feature incomplete!

# Building

## For *nix

* mkdir build
* cd build
* cmake -DDSLINK_BUILD_EXAMPLES=ON -DDSLINK_BUILD_BROKER=ON ..
* make
