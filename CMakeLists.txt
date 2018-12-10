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
# Optional components
# ------------------------------------------------------------------------------

# Build a bootable guest image
#
if(HK_BUILD_GUEST AND NOT WIN32 AND NOT CYGWIN)
    include(${HK_ERB_DIR}/CMakeLists.txt)
endif()


# Build the hyperkernel vmm
#
if(ENABLE_BUILD_VMM)

    # Note we start INTx at 0 rather than 1 per Appendix D.3 of the MP spec
    #
    set(PCI_INTA 0)
    set(PCI_INTB 1)
    set(PCI_INTC 2)
    set(PCI_INTD 3)

    if(${ERB_IMAGE} STREQUAL ndvm-iwlwifi)
        set(C_FLAGS   "-DNDVM_NIC_BUS=2 -DNDVM_NIC_DEV=0 -DNDVM_NIC_PIN=${PCI_INTA} -DNDVM_NIC_INTIN=19 -DNDVM_IOAPIC_ID=2")
        set(CXX_FLAGS "-DNDVM_NIC_BUS=2 -DNDVM_NIC_DEV=0 -DNDVM_NIC_PIN=${PCI_INTA} -DNDVM_NIC_INTIN=19 -DNDVM_IOAPIC_ID=2")
    endif()

    if(${ERB_IMAGE} STREQUAL ndvm-r8169)
        set(C_FLAGS   "-DNDVM_NIC_BUS=2 -DNDVM_NIC_DEV=0 -DNDVM_NIC_PIN=${PCI_INTA} -DNDVM_NIC_INTIN=16 -DNDVM_IOAPIC_ID=2")
        set(CXX_FLAGS "-DNDVM_NIC_BUS=2 -DNDVM_NIC_DEV=0 -DNDVM_NIC_PIN=${PCI_INTA} -DNDVM_NIC_INTIN=16 -DNDVM_IOAPIC_ID=2")
    endif()

    eapis_vmm_extension(
        hyperkernel_bfvmm
        SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfvmm/src
        C_FLAGS ${C_FLAGS}
        CXX_FLAGS ${CXX_FLAGS}
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
    SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/bfexec
    DEPENDS bfintrinsics
)
