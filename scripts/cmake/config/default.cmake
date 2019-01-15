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

# ------------------------------------------------------------------------------
# Source Tree
# ------------------------------------------------------------------------------

set(HK_SOURCE_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..
    CACHE INTERNAL
    "Hyperkernel Source root direfctory"
)

set(HK_SOURCE_CMAKE_DIR ${HK_SOURCE_ROOT_DIR}/scripts/cmake
    CACHE INTERNAL
    "Hyperkernel Cmake directory"
)

set(HK_SOURCE_CONFIG_DIR ${HK_SOURCE_ROOT_DIR}/scripts/cmake/config
    CACHE INTERNAL
    "Hyperkernel Cmake configurations directory"
)

set(HK_SOURCE_DEPENDS_DIR ${HK_SOURCE_ROOT_DIR}/scripts/cmake/depends
    CACHE INTERNAL
    "Hyperkernel Cmake dependencies directory"
)

set(HK_SOURCE_UTIL_DIR ${HK_SOURCE_ROOT_DIR}/scripts/util
    CACHE INTERNAL
    "Hyperkernel Utility directory"
)

set(HK_SOURCE_BFDRIVER_DIR ${HK_SOURCE_ROOT_DIR}/bfdriver
    CACHE INTERNAL
    "Hyperkernel bfdriver source dir"
)

set(HK_SOURCE_BFEXEC_DIR ${HK_SOURCE_ROOT_DIR}/bfexec
    CACHE INTERNAL
    "Hyperkernel bfexec source dir"
)

set(HK_SOURCE_BFSDK_DIR ${HK_SOURCE_ROOT_DIR}/bfsdk
    CACHE INTERNAL
    "Hyperkernel bfsdk source dir"
)

set(HK_SOURCE_BFVMM_DIR ${HK_SOURCE_ROOT_DIR}/bfvmm
    CACHE INTERNAL
    "Hyperkernel bfvmm source dir"
)

set(HK_SOURCE_ERB_DIR ${HK_SOURCE_ROOT_DIR}/erb
    CACHE INTERNAL
    "Hyperkernel erb source dir"
)

# ------------------------------------------------------------------------------
# Project-wide configs
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME HK_BUILD_GUEST
    CONFIG_TYPE BOOL
    DEFAULT_VAL ON
    DESCRIPTION "Build a guest image"
)

# ------------------------------------------------------------------------------
# ERB configs
#
# These variables enable users to customize the guest image that will be built,
# as well as the toolchain used to build it. If you are actively developing any
# of the sources used in the image, e.g. the linux kernel, you can specify an
# override path that will be passed to buildroot. This tells buildroot to build
# your override rather than the default upstream version.
# ------------------------------------------------------------------------------

add_config(
    CONFIG_NAME ERB_IMAGE
    CONFIG_TYPE STRING
    DEFAULT_VAL "ndvm-r8169"
    DESCRIPTION "The guest image to build"
    OPTIONS "tiny"
    OPTIONS "xenstore"
    OPTIONS "ndvm-r8169"
    OPTIONS "ndvm-brcmfmac"
)

add_config(
    CONFIG_NAME ERB_TUPLE
    CONFIG_TYPE STRING
    DEFAULT_VAL "x86_64-buildroot-linux-uclibc"
    DESCRIPTION "Tuple targeting the guest image"
    OPTIONS "x86_64-buildroot-linux-gnu"
    OPTIONS "x86_64-buildroot-linux-uclibc"
)

add_config(
    CONFIG_NAME ERB_TOOLS
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CACHE_DIR}/xtools
    DESCRIPTION "Canonical path to the toolchain"
)

add_config(
    CONFIG_NAME ERB_LINUX_OVERRIDE
    CONFIG_TYPE STRING
    DEFAULT_VAL "/home/dev/linux"
    DESCRIPTION "Path of linux source to override buildroot's default"
)

add_config(
    CONFIG_NAME ERB_ROOTFS_OVERLAY
    CONFIG_TYPE STRING
    DEFAULT_VAL "${HK_SOURCE_ERB_DIR}/overlay"
    DESCRIPTION "Directory to overlay onto the rootfs"
)

add_config(
    CONFIG_NAME ERB_FAKEROOT_HOOKS
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Script to execute in fakeroot context"
)
