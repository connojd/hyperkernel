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

if(WIN32 OR CYGWIN)
    return()
endif()

# ------------------------------------------------------------------------------
# Variables
# ------------------------------------------------------------------------------

set(BR_URL "https://buildroot.org/downloads/buildroot-2018.11.tar.gz"
    CACHE INTERNAL
    "Buildroot URL"
)

set(BR_URL_MD5 "1c140382fb8778b6c4458014e1fef4fb"
    CACHE INTERNAL
    "Buildroot URL MD5 hash"
)

set(BR_SRC_DIR ${CACHE_DIR}/buildroot CACHE INTERNAL "")
set(BR_BIN_DIR ${DEPENDS_DIR}/buildroot/${USERSPACE_PREFIX}/build/${ERB_IMAGE} CACHE INTERNAL "")
set(BR_CONFIG_IN ${HK_ERB_DIR}/image/${ERB_IMAGE}/buildroot.config.in CACHE INTERNAL "")
set(BR_CONFIG_OUT ${BR_BIN_DIR}/.config CACHE INTERNAL "")
set(BR_CONFIG_LINUX_IN ${HK_ERB_DIR}/image/${ERB_IMAGE}/linux.config.in CACHE INTERNAL "")
set(BR_CONFIG_LINUX_OUT ${BR_BIN_DIR}/.linux-config CACHE INTERNAL "")

if(ERB_LINUX_OVERRIDE)
    set(BR_OVERRIDE_IN ${HK_ERB_DIR}/image/${ERB_IMAGE}/override.mk.in CACHE INTERNAL "")
    message(STATUS "Using linux source: ${ERB_LINUX_OVERRIDE}")
else()
    set(BR_OVERRIDE_IN ${HK_ERB_DIR}/image/null-override.mk CACHE INTERNAL "")
    message(STATUS "Using linux source: https://github.com/connojd/linux.git")
endif()

set(BR_OVERRIDE_OUT ${BR_BIN_DIR}/override.mk CACHE INTERNAL "")

# ------------------------------------------------------------------------------
# Download
# ------------------------------------------------------------------------------

message(STATUS "Including dependency: buildroot")

download_dependency(
    buildroot
    URL         ${BR_URL}
    URL_MD5     ${BR_URL_MD5}
)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_dependency(
    buildroot userspace
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E touch_nocreate kludge
    BUILD_COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} olddefconfig
          COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR}
    INSTALL_COMMAND ${CMAKE_COMMAND} -E touch_nocreate kludge
    DEPENDS xtools_${USERSPACE_PREFIX}
)
