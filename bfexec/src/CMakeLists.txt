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

cmake_minimum_required(VERSION 3.6)
project(bfexec C CXX)

include(${SOURCE_CMAKE_DIR}/project.cmake)
init_project(
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../../bfvmm/include
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../../bfsdk/include
    INCLUDES ${CMAKE_CURRENT_LIST_DIR}/../include
)

if(BUILD_TARGET_OS STREQUAL "Linux")
    list(APPEND SOURCES
        platform/linux/ioctl.cpp
        platform/linux/ioctl_private.cpp
    )
    include_directories(platform/linux/)
elseif(BUILD_TARGET_OS STREQUAL "Windows")
    list(APPEND SOURCES
        platform/windows/ioctl.cpp
        platform/windows/ioctl_private.cpp
    )
    include_directories(platform/windows/)
else()
    message(FATAL_ERROR "Unsupported OS: ${BUILD_TARGET_OS}")
endif()

list(APPEND SOURCES
    main.cpp
)

add_executable(bfexec ${SOURCES})
target_link_static_libraries(bfexec bfintrinsics)

if(CYGWIN OR WIN32)
    target_link_libraries(bfexec setupapi)
endif()

if(UNIX)
    target_link_libraries(bfexec pthread)
endif()

install(TARGETS bfexec DESTINATION bin)
