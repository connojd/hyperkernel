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
# Project includes
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/scripts/cmake/config/default.cmake)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

include(${HK_SOURCE_CMAKE_DIR}/targets.cmake)

# ------------------------------------------------------------------------------
# VMs
# ------------------------------------------------------------------------------

#if(HK_BUILD_GUEST AND NOT WIN32 AND NOT CYGWIN)
#    include(${HK_SOURCE_ERB_DIR}/CMakeLists.txt)
#endif()


# ------------------------------------------------------------------------------
# VMM
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_VMM)
    eapis_vmm_extension(
        hyperkernel_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
    )

    eapis_vmm_extension(
        hyperkernel_bfvmm_main
        DEPENDS hyperkernel_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
    )
endif()

# ------------------------------------------------------------------------------
# bfexec
# ------------------------------------------------------------------------------

userspace_extension(
    bfexec
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfexec/src
    DEPENDS bfintrinsics
    DEPENDS cxxopts
)
