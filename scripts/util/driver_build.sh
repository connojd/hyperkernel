#!/bin/bash -e
#
# Bareflank Hyperkernel
# Copyright (C) 2018 Assured Information Security, Inc.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

# $1 == HK_SOURCE_ROOT_DIR
# $2 == SOURCE_ROOT_DIR

msbuild_2015="/cygdrive/c/Program Files (x86)/MSBuild/14.0/Bin/MSBuild.exe"
msbuild_2017="/cygdrive/c/Program Files (x86)/Microsoft Visual Studio/2017/Community/MSBuild/15.0/bin/msbuild.exe"

find_msbuild() {

    if [[ -f $msbuild_2017 ]]; then
        msbuild=$msbuild_2017
        return
    fi

    if [[ -f $msbuild_2015 ]]; then
        msbuild=$msbuild_2015
        return
    fi

    >&2 echo "ERROR: failed to find msbuild"
    exit 1
}

case $(uname -s) in
CYGWIN_NT-6.1*)
    find_msbuild
    cd $1/bfdriver/builder/src/platform/windows/
    SOURCE_ROOT_DIR=`cygpath -w -m $2`
    >&2 eval "'$msbuild' /p:SOURCE_ROOT_DIR=$SOURCE_ROOT_DIR /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=Windows7 builder.sln"

    cd $1/bfdriver/visr/src/platform/windows/
    SOURCE_ROOT_DIR=`cygpath -w -m $2`
    >&2 eval "'$msbuild' /p:SOURCE_ROOT_DIR=$SOURCE_ROOT_DIR /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=Windows7 visr.sln"
    ;;
CYGWIN_NT-6.3*)
    find_msbuild
    cd $1/bfdriver/builder/src/platform/windows/
    SOURCE_ROOT_DIR=`cygpath -w -m $2`
    >&2 eval "'$msbuild' /p:SOURCE_ROOT_DIR=$SOURCE_ROOT_DIR /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=WindowsV6.3 builder.sln"

    cd $1/bfdriver/visr/src/platform/windows/
    SOURCE_ROOT_DIR=`cygpath -w -m $2`
    >&2 eval "'$msbuild' /p:SOURCE_ROOT_DIR=$SOURCE_ROOT_DIR /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=Windows7 visr.sln"
    ;;
CYGWIN_NT-10.0*)
    find_msbuild
    cd $1/bfdriver/builder/src/platform/windows/
    SOURCE_ROOT_DIR=`cygpath -w -m $2`
    >&2 eval "'$msbuild' /p:SOURCE_ROOT_DIR=$SOURCE_ROOT_DIR /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=Windows10 builder.sln"

    cd $1/bfdriver/visr/src/platform/windows/
    SOURCE_ROOT_DIR=`cygpath -w -m $2`
    >&2 eval "'$msbuild' /p:SOURCE_ROOT_DIR=$SOURCE_ROOT_DIR /m:3 /p:Configuration=Release /p:Platform=x64 /p:TargetVersion=Windows7 visr.sln"
    ;;
Linux)
    cd $1/bfdriver/builder/src/platform/linux
    make SOURCE_ROOT_DIR=$2 -j3
    ;;
*)
    >&2 echo "OS not supported"
    exit 1
esac
