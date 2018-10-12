#
# Bareflank Hypervisor
# Copyright (C) 2015 Assured Information Security, Inc.
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

cmake_minimum_required(VERSION 3.6)
project(hyperkernel_tests ASM C)

include_directories(${SOURCE_BFSDK_DIR}/include/)
include_directories(${CMAKE_CURRENT_LIST_DIR}/../include/)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# set(CMAKE_C_FLAGS "--target=x86_64-vmm-elf --sysroot=${VMM_PREFIX_PATH}")
# set(CMAKE_CXX_FLAGS "--target=x86_64-vmm-elf --sysroot=${VMM_PREFIX_PATH}")

add_executable(test_hyperkernel_basic_${TYPE} test_hyperkernel_basic.c start.s)
target_link_libraries(test_hyperkernel_basic_${TYPE} bfintrinsics_static)

install(TARGETS test_hyperkernel_basic_${TYPE} DESTINATION bin)
