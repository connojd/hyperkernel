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

add_custom_target_category("Guest Image \\(${ERB_IMAGE}\\)")

include_dependency(HK_DEPEND_DIR xtools)
include_dependency(HK_DEPEND_DIR buildroot)

add_custom_target(vm COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR})
add_custom_target(vm-clean COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} clean)
add_custom_target(vm-distclean COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} distclean)

add_dependencies(vm buildroot_${USERSPACE_PREFIX})

add_custom_target_info(TARGET vm COMMENT "Build the VM")
add_custom_target_info(TARGET vm-clean COMMENT "Remove the VM build files")
add_custom_target_info(TARGET vm-distclean COMMENT "Remove the VM build and config files")

# ------------------------------------------------------------------------------
# Guest VM targets
# ------------------------------------------------------------------------------

add_custom_target(linux-source
    COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} linux-source
    USES_TERMINAL
)
add_custom_target_info(TARGET linux-source COMMENT "Fetch the kernel source")

add_custom_target(linux-build
    COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} linux-build
    USES_TERMINAL
)
add_custom_target_info(TARGET linux-build COMMENT "Build the kernel")

add_custom_target(linux-reconfig
    COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} linux-reconfigure
    USES_TERMINAL
)
add_custom_target_info(TARGET linux-reconfig COMMENT "Restart kernel build from configure step")

add_custom_target(linux-rebuild
    COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} linux-rebuild
    USES_TERMINAL
)
add_custom_target_info(TARGET linux-rebuild COMMENT "Restart kernel build from build step")

add_custom_target(linux-dirclean
    COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} linux-dirclean
    USES_TERMINAL
)
add_custom_target_info(TARGET linux-dirclean COMMENT "Remove kernel build files")

add_custom_target(linux-patch
    COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} linux-patch
    USES_TERMINAL
)
add_custom_target_info(TARGET linux-patch COMMENT "Patch the kernel")

add_custom_target(linux-mc
    COMMAND ${CMAKE_COMMAND} -E copy ${BR_CONFIG_LINUX_IN} ${BR_CONFIG_LINUX_OUT}
    COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} linux-menuconfig
    COMMAND ${CMAKE_COMMAND} -E copy ${BR_CONFIG_LINUX_OUT} ${BR_CONFIG_LINUX_IN}
    USES_TERMINAL
)
add_custom_target_info(TARGET linux-mc COMMENT "Run linux menuconfig")

add_custom_target(buildroot-mc
    COMMAND ${CMAKE_COMMAND} -E copy ${BR_CONFIG_IN} ${BR_CONFIG_OUT}
    COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} menuconfig
    COMMAND ${CMAKE_COMMAND} -E copy ${BR_CONFIG_OUT} ${BR_CONFIG_IN}
    USES_TERMINAL
)
add_custom_target_info(TARGET buildroot-mc COMMENT "Run buildroot menuconfig")

# ------------------------------------------------------------------------------
# Reconfigure steps
# ------------------------------------------------------------------------------

ExternalProject_Add_Step(buildroot_${USERSPACE_PREFIX} reconfig-linux
    COMMAND ${CMAKE_COMMAND}
        -DFILE_CONFIG_IN=${BR_CONFIG_LINUX_IN}
        -DFILE_CONFIG_OUT=${BR_CONFIG_LINUX_OUT}
        -P ${HK_CMAKE_DIR}/config/reconfig.cmake
    COMMAND ${CMAKE_COMMAND} --build . --target linux-reconfig
    DEPENDS ${BR_CONFIG_LINUX_IN} ${BR_OVERRIDE_IN}
    COMMENT "Re-configuring linux"
)

ExternalProject_Add_Step(buildroot_${USERSPACE_PREFIX} reconfig-buildroot
    COMMAND ${CMAKE_COMMAND}
        -DFILE_CONFIG_IN=${BR_CONFIG_IN}
        -DFILE_CONFIG_OUT=${BR_CONFIG_OUT}
        -DBR_CONFIG_LINUX=${BR_CONFIG_LINUX}
        -P ${HK_CMAKE_DIR}/config/reconfig.cmake
    DEPENDEES reconfig-linux
    DEPENDERS build
    DEPENDS ${BR_CONFIG_IN}
    COMMENT "Re-configuring buildroot"
)

