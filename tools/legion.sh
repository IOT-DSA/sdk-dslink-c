#!/usr/bin/env bash
set -e

ANSI=$(dirname ${0})/utils/ansi.sh

function status() {
  ${ANSI} --newline --green "${@}"
}

if [ -z $(which legion) ]
then
  status Installing Legion...
  pub global activate -sgit https://github.com/IOT-DSA/legion.git
  status Legion is now installed.
fi

pub global run legion "${@}"
