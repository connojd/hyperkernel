#
# Bareflank Hypervisor
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
# VMM Components
# ------------------------------------------------------------------------------

if(ENABLE_BUILD_VMM)
    eapis_vmm_extension(
        hyperkernel_bfvmm_main
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
    )
#     add_subproject(
#         eapis_bfvmm vmm
#         DEPENDS bfvmm
#         DEPENDS bfintrinsics
#         DEPENDS capstone
#         SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
#     )

#     add_subproject(
#         eapis_bfvmm_main vmm
#         DEPENDS eapis_bfvmm
#         SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
#     )

#     add_subproject(
#         eapis_integration vmm
#         DEPENDS eapis_bfvmm
#         SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/integration/
#     )
endif()

# ------------------------------------------------------------------------------
# Unit Tests
# ------------------------------------------------------------------------------

# if(ENABLE_BUILD_TEST)
#     add_subproject(
#         eapis_bfvmm test
#         DEPENDS bfvmm
#         DEPENDS capstone
#         SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/tests/
#     )

#     add_subproject(
#         eapis_bfsdk test
#         DEPENDS bfvmm
#         DEPENDS capstone
#         SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfsdk/tests/
#     )
# endif()

# ------------------------------------------------------------------------------
# Extensions
# ------------------------------------------------------------------------------

userspace_extension(
    exec
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfexec
    DEPENDS bfintrinsics
)
