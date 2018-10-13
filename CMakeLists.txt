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
        hyperkernel_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
    )

    eapis_vmm_extension(
        hyperkernel_bfvmm_main
        DEPENDS hyperkernel_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src/main
    )

    include(${CMAKE_CURRENT_LIST_DIR}/bfdriver/CMakeLists.txt)
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
# Tests (PIE)
# ------------------------------------------------------------------------------

list(APPEND HYPERKERNEL_TESTS_PIE_CMAKE_ARGS
    -DTYPE=pie
    -DSOURCE_BFSDK_DIR=${SOURCE_BFSDK_DIR}
    -DCMAKE_INSTALL_PREFIX=${VMM_PREFIX_PATH}
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_LIST_DIR}/tests/clang_x86_64_tests_pie.cmake
)

ExternalProject_Add(
    hyperkernel_tests_pie
    CMAKE_ARGS ${HYPERKERNEL_TESTS_PIE_CMAKE_ARGS}
    PREFIX ${CMAKE_BINARY_DIR}/hyperkernel_tests_pie/pie/prefix
    TMP_DIR ${CMAKE_BINARY_DIR}/hyperkernel_tests_pie/pie/tmp
    STAMP_DIR ${CMAKE_BINARY_DIR}/hyperkernel_tests_pie/pie/stamp
    DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/hyperkernel_tests_pie/pie/download
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/tests/
    BINARY_DIR ${CMAKE_BINARY_DIR}/hyperkernel_tests_pie/pie/build
    UPDATE_COMMAND  ${CMAKE_COMMAND} -E echo "-- checking for updates"
)

add_dependencies(hyperkernel_tests_pie bfvmm_${VMM_PREFIX})

# ------------------------------------------------------------------------------
# Tests (No PIE)
# ------------------------------------------------------------------------------

list(APPEND HYPERKERNEL_TESTS_NOPIE_CMAKE_ARGS
    -DTYPE=nopie
    -DSOURCE_BFSDK_DIR=${SOURCE_BFSDK_DIR}
    -DCMAKE_INSTALL_PREFIX=${VMM_PREFIX_PATH}
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_LIST_DIR}/tests/clang_x86_64_tests_nopie.cmake
)

ExternalProject_Add(
    hyperkernel_tests_nopie
    CMAKE_ARGS ${HYPERKERNEL_TESTS_NOPIE_CMAKE_ARGS}
    PREFIX ${CMAKE_BINARY_DIR}/hyperkernel_tests_nopie/nopie/prefix
    TMP_DIR ${CMAKE_BINARY_DIR}/hyperkernel_tests_nopie/nopie/tmp
    STAMP_DIR ${CMAKE_BINARY_DIR}/hyperkernel_tests_nopie/nopie/stamp
    DOWNLOAD_DIR ${CMAKE_BINARY_DIR}/hyperkernel_tests_nopie/nopie/download
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/tests/
    BINARY_DIR ${CMAKE_BINARY_DIR}/hyperkernel_tests_nopie/nopie/build
    UPDATE_COMMAND  ${CMAKE_COMMAND} -E echo "-- checking for updates"
)

add_dependencies(hyperkernel_tests_nopie bfvmm_${VMM_PREFIX})

# ------------------------------------------------------------------------------
# bfexec
# ------------------------------------------------------------------------------

userspace_extension(
    bfexec
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfexec
    DEPENDS bfintrinsics
)

if(NOT WIN32)
    add_custom_target(hkd-test
        COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfexec
        DEPENDS bfexec_${USERSPACE_PREFIX}
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET hkd-test
        COMMENT "Test the hyperkernel driver"
    )
endif()
