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
# Constants
# ------------------------------------------------------------------------------

set(HK_ROOT_DIR ${CMAKE_CURRENT_LIST_DIR}/../../.. CACHE INTERNAL "")
set(HK_CMAKE_DIR ${HK_ROOT_DIR}/scripts/cmake CACHE INTERNAL "")
set(HK_CONFIG_DIR ${HK_ROOT_DIR}/scripts/cmake/config CACHE INTERNAL "")
set(HK_DEPEND_DIR ${HK_ROOT_DIR}/scripts/cmake/depends CACHE INTERNAL "")
set(HK_ERB_DIR ${HK_ROOT_DIR}/erb CACHE INTERNAL "")

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
    DEFAULT_VAL "tiny"
    DESCRIPTION "The guest image to build"
    OPTIONS "tiny"
)

add_config(
    CONFIG_NAME ERB_TUPLE
    CONFIG_TYPE STRING
    DEFAULT_VAL "x86_64-erb-linux-gnu"
    DESCRIPTION "Tuple targeting the guest image"
    OPTIONS "x86_64-erb-linux-gnu"
)

add_config(
    CONFIG_NAME ERB_TOOLS
    CONFIG_TYPE STRING
    DEFAULT_VAL ${CACHE_DIR}/${ERB_TUPLE}
    DESCRIPTION "Canonical path to the toolchain"
)

add_config(
    CONFIG_NAME ERB_LINUX_OVERRIDE
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Path of linux source to override buildroot's default"
)

add_config(
    CONFIG_NAME ERB_ROOTFS_OVERLAY
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Directory to overlay onto the rootfs"
)

add_config(
    CONFIG_NAME ERB_FAKEROOT_HOOKS
    CONFIG_TYPE STRING
    DEFAULT_VAL ""
    DESCRIPTION "Script to execute in fakeroot context"
)

