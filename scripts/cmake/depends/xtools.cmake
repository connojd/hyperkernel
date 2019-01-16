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
# Cross-compiler variables
# ------------------------------------------------------------------------------

set(ERB_TOOLS_URL "https://github.com/connojd/xtools/releases/download/v0.6.0/${ERB_TUPLE}_sdk-buildroot.tar.gz"
    CACHE INTERNAL FORCE
    "Cross-compiler URL"
)

set(ERB_TOOLS_URL_MD5 "736b79c033eabf51c6385e83758039b3"
    CACHE INTERNAL FORCE
    "Cross-compiler URL MD5 hash"
)

# ------------------------------------------------------------------------------
# Download
# ------------------------------------------------------------------------------

message(STATUS "Including dependency: xtools (${ERB_TUPLE})")

download_dependency(
    xtools
    URL     ${ERB_TOOLS_URL}
    URL_MD5 ${ERB_TOOLS_URL_MD5}
)

add_dependency(
    xtools userspace
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E chdir ${CACHE_DIR}/xtools ./relocate-sdk.sh
    BUILD_COMMAND     ${CMAKE_COMMAND} -E touch_nocreate kludge
    INSTALL_COMMAND   ${CMAKE_COMMAND} -E touch_nocreate kludge
)
