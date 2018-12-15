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

include_dependency(HK_SOURCE_DEPENDS_DIR xtools)
include_dependency(HK_SOURCE_DEPENDS_DIR buildroot)

# ------------------------------------------------------------------------------
# Top-level targets
# ------------------------------------------------------------------------------

add_custom_target(vm COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR})
add_custom_target(vm-run COMMAND ${SUDO} ${USERSPACE_PREFIX_PATH}/bin/bfexec ${PREFIXES_DIR}/vm/vmlinux)
add_custom_target(vm-clean COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} clean)
add_custom_target(vm-distclean COMMAND make O=${BR_BIN_DIR} -C ${BR_SRC_DIR} distclean)

add_custom_target_info(TARGET vm COMMENT "Build the VM")
add_custom_target_info(TARGET vm-run COMMENT "Run the VM")
add_custom_target_info(TARGET vm-clean COMMENT "Clean build files")
add_custom_target_info(TARGET vm-distclean COMMENT "Clean build and config files")

set(BR_TARGET buildroot_${USERSPACE_PREFIX})

# ------------------------------------------------------------------------------
# Reconfigure steps
# ------------------------------------------------------------------------------

ExternalProject_Add_Step(${BR_TARGET} reconfig-overrides
    COMMAND ${CMAKE_COMMAND}
        -DFILE_CONFIG_IN=${BR_OVERRIDE_IN}
        -DFILE_CONFIG_OUT=${BR_OVERRIDE_OUT}
        -DERB_LINUX_OVERRIDE=${ERB_LINUX_OVERRIDE}
        -P ${HK_SOURCE_CMAKE_DIR}/config/reconfig.cmake
    DEPENDEES configure
    DEPENDS ${BR_OVERRIDE_IN}
    COMMENT "Re-configuring override sources"
)

ExternalProject_Add_Step(${BR_TARGET} reconfig-linux
    COMMAND ${CMAKE_COMMAND}
        -DFILE_CONFIG_IN=${BR_CONFIG_LINUX_IN}
        -DFILE_CONFIG_OUT=${BR_CONFIG_LINUX_OUT}
        -DERB_IMAGE=${ERB_IMAGE}
        -P ${HK_SOURCE_CMAKE_DIR}/config/reconfig.cmake
    DEPENDEES reconfig-overrides
    DEPENDS ${BR_CONFIG_LINUX_IN}
    COMMENT "Re-configuring linux"
)

ExternalProject_Add_Step(${BR_TARGET} reconfig-buildroot
    COMMAND ${CMAKE_COMMAND}
        -DFILE_CONFIG_IN=${BR_CONFIG_IN}
        -DFILE_CONFIG_OUT=${BR_CONFIG_OUT}
        -DBR_CONFIG_LINUX_OUT=${BR_CONFIG_LINUX_OUT}
        -DBR_OVERRIDE_OUT=${BR_OVERRIDE_OUT}
        -DERB_IMAGE=${ERB_IMAGE}
        -DERB_TUPLE=${ERB_TUPLE}
        -DERB_TOOLS=${ERB_TOOLS}
        -DERB_ROOTFS_OVERLAY=${ERB_ROOTFS_OVERLAY}
        -DERB_FAKEROOT_HOOKS=${ERB_FAKEROOT_HOOKS}
        -P ${HK_SOURCE_CMAKE_DIR}/config/reconfig.cmake
    DEPENDEES reconfig-linux
    DEPENDERS build
    DEPENDS ${BR_CONFIG_IN}
    COMMENT "Re-configuring buildroot"
)

ExternalProject_Add_Step(${BR_TARGET} vm-install
    COMMAND ${CMAKE_COMMAND} -E make_directory ${PREFIXES_DIR}/vm
    COMMAND ${CMAKE_COMMAND} -E copy ${BR_BIN_DIR}/images/vmlinux ${PREFIXES_DIR}/vm
    DEPENDEES build
    COMMENT "Installed vm: ${ERB_IMAGE}"
)

add_dependencies(vm ${BR_TARGET})
add_dependencies(vm-run vm)

# ------------------------------------------------------------------------------
# Menuconfig targets
# ------------------------------------------------------------------------------

if(ERB_LINUX_OVERRIDE)
    set(SUFFIX "custom")
else()
    set(SUFFIX "hk")
endif()
set(LINUX_BIN_DIR ${BR_BIN_DIR}/build/linux-${SUFFIX})

add_custom_target(lmc
    COMMAND ${HK_SOURCE_UTIL_DIR}/menuconfig.sh ${LINUX_BIN_DIR} ${BR_CONFIG_LINUX_IN}
    USES_TERMINAL
)
add_custom_target(bmc
    COMMAND ${HK_SOURCE_UTIL_DIR}/menuconfig.sh ${BR_BIN_DIR} ${BR_CONFIG_IN}
    USES_TERMINAL
)

add_custom_target_info(TARGET lmc COMMENT "Run linux\\'s menuconfig")
add_custom_target_info(TARGET bmc COMMENT "Run buildroot\\'s menuconfig")
