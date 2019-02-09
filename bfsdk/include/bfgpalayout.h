/**
 * Bareflank Hyperkernel
 * Copyright (C) 2018 Assured Information Security, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef BFGPALAYOUT_H
#define BFGPALAYOUT_H

#include <bftypes.h>
#include <bfdebug.h>
#include <bferrorcodes.h>

#define XEN_HVM_MEMMAP_TYPE_RAM       1
#define XEN_HVM_MEMMAP_TYPE_RESERVED  2
#define XEN_HVM_MEMMAP_TYPE_ACPI      3
#define XEN_HVM_MEMMAP_TYPE_NVS       4
#define XEN_HVM_MEMMAP_TYPE_UNUSABLE  5
#define XEN_HVM_MEMMAP_TYPE_DISABLED  6
#define XEN_HVM_MEMMAP_TYPE_PMEM      7

/**
 * Below defines the memory map that is used by the guest, and this memory
 * map will be provided to the VMM, which in turn will be provided to the
 * a Linux guest when it boots.
 *
 *           0x0 +----------------------+ ---
 *               | RAM                  |  | RAM (BIOS RAM)
 *       0xE8000 +----------------------+ ---
 *               | Initial GDT          |  | Reserved
 *       0xE9000 +----------------------+  |
 *               | Initial IDT          |  |
 *       0xEA000 +----------------------+  |
 *               | Initial TSS          |  |
 *       0xEB000 +----------------------+  |
 *               | Xen Start Info       |  |
 *       0xEC000 +----------------------+  |
 *               | Xen CMD Line         |  |
 *       0xED000 +----------------------+  |
 *               | Xen Console Page     |  |
 *       0xEE000 +----------------------+  |
 *               | Free                 |  |
 *       0xEF000 +----------------------+  |
 *               | Free                 |  |
 *       0xF0000 +----------------------+  |
 *               | RSDP                 |  |
 *       0xF1000 +----------------------+  |
 *               | XSDT                 |  |
 *       0xF2000 +----------------------+  |
 *               | MADT                 |  |
 *       0xF3000 +----------------------+  |
 *               | FADT                 |  |
 *       0xF4000 +----------------------+  |
 *               | DSDT                 |  |
 *       0xF5000 +----------------------+  |
 *               | Free                 |  |
 *      0x100000 +----------------------+ ---
 *               | Unusable             |  | Unusable
 *     0x1000000 +----------------------+ ---
 *               | Linux ELF (Xen PVH)  |  | RAM
 *           XXX +----------------------+  |
 *               | Usable RAM           |  |
 *    0xXXXXXXXX +----------------------+ ---
 *               | Unusable             |  | Unusable
 *    0xFEC00000 +----------------------+ ---
 *               | IOAPIC               |  | Reserved
 *    0xFEC01000 +----------------------+  |
 *               | Free                 |  |
 *    0xFEE00000 +----------------------+  |
 *               | Local APIC           |  |
 *    0xFEE01000 +----------------------+  |
 *               | Free                 |  |
 *    0xFFFFFFFF +----------------------+ ---
 *               | Unusable             |  | Unusable
 *           ... +----------------------+ ---
 *
 * All RAM addresses must have backing memory, and must be mapped as RWE as this
 * is memory that the kernel could attempt to use. Reserved memory can be
 * mapped as both RO and RW and does not need backing (meaning this memory does
 * not have to all be mapped). Unusable memory cannot not be mapped.
 *
 * The VMM's vmcalls will enforce the above rules, so if you are having problems
 * mapping in additional memory, you likely need to addjust the E820 map to get
 * it to work. If you do make changes, please update the above map so that what
 * is being mapped into the guest is well documented.
 */

int64_t
add_e820_entry(void *vm, uint64_t saddr, uint64_t eaddr, uint32_t type);

/**
 * Setup E820 Map
 *
 * This function uses the add_e820_entry function to tell the VMM what the E820
 * map is for a given guest VM. This information is used by the hypervisor
 * when mapping memory, and it is also provided to the guest VM if it asks for
 * it using the Xen PV interface.
 *
 * @expects size < 0xFDC00000. Right now we do not support more than 4gb of
 *     RAM, so this is the typical limitation for a < 4GB VM as you must remove
 *     BIOS and hardware addresses spaces from your 4GB limit
 *
 * @param vm a pointer to a VM object that is needed by add_e820_entry
 * @param size the amound of RAM given to the VM. Note that this amount does
 *     not include the RAM in the initial BIOS region that is also given to
 *     the VM.
 * @return SUCCESS on success, FAILURE otherwise
 */
static inline int64_t
setup_e820_map(void *vm, uint64_t vmlinux_size, uint64_t initrd_size)
{
    status_t ret = 0;

    if (vmlinux_size >= 0xFDC00000) {
        BFALERT("setup_e820_map: unsupported amount of RAM\n");
        return FAILURE;
    }

    /**
     * TODO: Linux is assigning memory to PCI only if it isn't specified in the e820. This doesn't
     * seem right but for now we leave a gap for PCI.
     */
    ret |= add_e820_entry(vm, 0x0000000000000000, 0x00000000000E8000, XEN_HVM_MEMMAP_TYPE_RAM);
    ret |= add_e820_entry(vm, 0x00000000000E8000, 0x0000000000100000, XEN_HVM_MEMMAP_TYPE_RESERVED);
    ret |= add_e820_entry(vm, 0x0000000000100000, 0x0000000001000000, XEN_HVM_MEMMAP_TYPE_UNUSABLE);
    ret |= add_e820_entry(vm, 0x0000000001000000, 0x001000000 + vmlinux_size + initrd_size, XEN_HVM_MEMMAP_TYPE_RAM);
//    ret |= add_e820_entry(vm, 0x001000000 + size, 0x00F0000000, XEN_HVM_MEMMAP_TYPE_UNUSABLE);
//    ret |= add_e820_entry(vm, 0x00F7100000, 0x00F8000000, XEN_HVM_MEMMAP_TYPE_UNUSABLE);
    ret |= add_e820_entry(vm, 0x00000000F8000000, 0x00000000F8001000, XEN_HVM_MEMMAP_TYPE_RESERVED); // mmcfg
    ret |= add_e820_entry(vm, 0x00000000FEC00000, 0xFEC01000, XEN_HVM_MEMMAP_TYPE_UNUSABLE);
//    ret |= add_e820_entry(vm, 0x00000000FFFFFFFF, 0xFFFFFFFFFFFFFFFF, XEN_HVM_MEMMAP_TYPE_UNUSABLE);

    if (ret != SUCCESS) {
        BFALERT("setup_e820_map: add_e820_entry failed to add E820 entries\n");
        return FAILURE;
    }

    return SUCCESS;
}

#define BIOS_RAM_ADDR       0x0
#define BIOS_RAM_SIZE       0xE8000

#define RESERVED1_ADRR      0xEE000
#define RESERVED1_SIZE      0x02000

#define RESERVED2_ADRR      0xF7000
#define RESERVED2_SIZE      0x09000

#define INITIAL_GDT_GPA     0xE8000
#define INITIAL_IDT_GPA     0xE9000
#define INITIAL_TSS_GPA     0xEA000

#define XEN_START_INFO_PAGE_GPA     0xEB000
#define XEN_COMMAND_LINE_PAGE_GPA   0xEC000
#define XEN_CONSOLE_PAGE_GPA        0xED000
#define XEN_MODLIST_GPA             0xF6000

#define ACPI_RSDP_GPA       0xF0000
#define ACPI_XSDT_GPA       0xF1000
#define ACPI_MADT_GPA       0xF2000
#define ACPI_FADT_GPA       0xF3000
#define ACPI_DSDT_GPA       0xF4000
#define ACPI_MCFG_GPA       0xF5000

#define LAPIC_GPA           0xFEE00000
#define IOAPIC_GPA          0xFEC00000

#define START_ADDR          0x1000000

#endif
