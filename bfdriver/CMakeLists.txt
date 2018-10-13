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

if(NOT WIN32)
    add_custom_target_category("Hyperkernel Driver")

    add_custom_target(hkd-build
        COMMAND make -C ${CMAKE_CURRENT_LIST_DIR}/src/platform/linux
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET hkd-build
        COMMENT "Build the hyperkernel driver"
    )

    add_custom_target(hkd-clean
        COMMAND make -C ${CMAKE_CURRENT_LIST_DIR}/src/platform/linux clean
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET hkd-clean
        COMMENT "Clean the hyperkernel driver"
    )

    add_custom_target(hkd-load
        COMMAND ${SUDO} make -C ${CMAKE_CURRENT_LIST_DIR}/src/platform/linux load
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET hkd-load
        COMMENT "Load the hyperkernel driver"
    )

    add_custom_target(hkd-unload
        COMMAND ${SUDO} make -C ${CMAKE_CURRENT_LIST_DIR}/src/platform/linux unload
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET hkd-unload
        COMMENT "Unload the hyperkernel driver"
    )

    add_custom_target(
        hkd-quick
        COMMAND ${CMAKE_COMMAND} --build . --target hkd-unload
        COMMAND ${CMAKE_COMMAND} --build . --target hkd-clean
        COMMAND ${CMAKE_COMMAND} --build . --target hkd-build
        COMMAND ${CMAKE_COMMAND} --build . --target hkd-load
        USES_TERMINAL
    )
    add_custom_target_info(
        TARGET hkd-quick
        COMMENT "Unload, clean, build, and load the hyperkernel driver"
    )
endif()
