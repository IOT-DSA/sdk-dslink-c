#!/bin/bash

# @copyright_start
# Copyright (c) 2016 Cisco and/or its affiliates. All rights reserved.
# @copyright_end

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# get OS and OS Version
# examples:
#
# getos.sh [--full]
#    Debian7
#    Ubuntu12.04
#    CentOS7
#    SLES11sp2
#
# getos.sh [--distro]
#    Debian
#    Ubuntu
#    CentOS7
#    SLES11sp2
#
# getos.sh [--version]
#    7
#    10.04
#    7
#    11sp2
#
# getos.sh [--fulldistro]
# only used in revision.h and for ps_info_version
#    Debian GNU/Linux 6.0.6 (squeeze)
#    Ubuntu 12.04.4 LTS

shopt -s extglob

# exists on debian and ubuntu
if [ -e /etc/debian_version ]
then
  DISTRO=`lsb_release -s -i`
  VERSION=`lsb_release -s -r`
  FULLDISTRO=$(lsb_release -s -d)
  if [ "$DISTRO" == "Debian" ]
  then
    SPLITVERSION=( ${VERSION//./ } )
    VERSION=${SPLITVERSION[0]}
  fi 
else
  # check for cent version
  # untested on redhat
  if [ -e /etc/redhat-release ]
  then
    DISTRO=`awk '{print $1}' /etc/redhat-release`
    FULLVERSION=`awk '{print $3}' /etc/redhat-release`
    SPLITVERSION=( ${FULLVERSION//./ } )
    VERSION=${SPLITVERSION[0]}
    # CentOS 7 file differs
    if [ "$VERSION" == "release" ]
    then
      FULLVERSION=`awk '{print $4}' /etc/redhat-release`
      SPLITVERSION=( ${FULLVERSION//./ } )
      VERSION=${SPLITVERSION[0]}
    fi
    FULLDISTRO=$(cat /etc/redhat-release)
  fi
  # check for SuSE version
  if [ -e /etc/SuSE-release ]
  then
    DISTRO="SLES"
    VER=`grep "^VERSION" /etc/SuSE-release | awk '{print $3}'`
    SP=`grep "^PATCHLEVEL" /etc/SuSE-release | awk '{print $3}'`
    VERSION="${VER}"sp"${SP}"
    FULLDISTRO=$(cat /etc/SuSE-release | sed -e 's/#.*$//' | xargs)
  fi
fi

# if distro not set check for Mac OS X
if [[ -z "$DISTRO" ]]
then
  if type "sw_vers" > /dev/null;
  then
    OSXDISTRO=$(sw_vers -productName)
    DISTRO="${OSXDISTRO//+([[:space:]])/}"
    FULLVERSION=$(sw_vers -productVersion)
    SPLITVERSION=( ${FULLVERSION//./ } )
    VERSION=${SPLITVERSION[0]}"."${SPLITVERSION[1]}
  fi
fi

# No distro :(
if [[ -z "$DISTRO" ]]
then
  echo "${0} could not find Operating System"
  exit 1
fi
if [[ -z "$VERSION" ]]
then
  echo "${0} could not find Operating System Version"
  exit 1
fi

# check arguments
if [ "$#" -eq 0 ]
then
  echo "$DISTRO$VERSION"
else
  case "$1" in
    "--full")
      echo "$DISTRO$VERSION"
      ;;
    "--distro")
      echo "$DISTRO"
      ;;
    "--version")
      echo "$VERSION"
      ;;
    "--fulldistro")
      echo "$FULLDISTRO"
      ;;
    *)
      echo "Unknown option: $1."
      exit 1;
  esac
fi
