/*
 * Bareflank Hypervisor
 * Copyright (C) 2015 Assured Information Security, Inc.
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

#include <common.h>

#include <bfdebug.h>
#include <bfconstants.h>
#include <bfgpalayout.h>
#include <bfhypercall.h>

#define bfalloc_page(a) \
    (a *)platform_memset(platform_alloc_rwe(BAREFLANK_PAGE_SIZE), 0, BAREFLANK_PAGE_SIZE);
#define bfalloc_buffer(a,b) \
    (a *)platform_memset(platform_alloc_rwe(b), 0, b);

/* -------------------------------------------------------------------------- */
/* E820 Functions                                                             */
/* -------------------------------------------------------------------------- */

int64_t
add_e820_entry(void *vm, uint64_t saddr, uint64_t eaddr, uint32_t type)
{
    status_t ret;
    struct vm_t *_vm = (struct vm_t *)vm;

    ret = __domain_op__add_e820_entry(_vm->domainid, saddr, eaddr - saddr, type);
    if (ret != SUCCESS) {
        BFDEBUG("__domain_op__add_e820_entry: failed\n");
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* Donate Functions                                                           */
/* -------------------------------------------------------------------------- */

static status_t
donate_page(
    struct vm_t *vm, void *gva, uint64_t domain_gpa, uint64_t type)
{
    status_t ret;
    uint64_t gpa = (uint64_t)platform_virt_to_phys(gva);

    ret = __domain_op__share_page(vm->domainid, gpa, domain_gpa, type);
    if (ret != SUCCESS) {
        BFDEBUG("donate_page: __domain_op__donate_gpa failed\n");
    }

    return ret;
}

static status_t
donate_buffer(
    struct vm_t *vm, void *gva, uint64_t domain_gpa, uint64_t size, uint64_t type)
{
    uint64_t i;
    status_t ret = SUCCESS;

    for (i = 0; i < size; i += BAREFLANK_PAGE_SIZE) {
        ret = donate_page(vm, (char *)gva + i, domain_gpa + i, type);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return ret;
}

static status_t
donate_page_to_page_range(
    struct vm_t *vm, void *gva, uint64_t domain_gpa, uint64_t size, uint64_t type)
{
    uint64_t i;
    status_t ret = SUCCESS;

    for (i = 0; i < size; i += BAREFLANK_PAGE_SIZE) {
        ret = donate_page(vm, gva, domain_gpa + i, type);
        if (ret != SUCCESS) {
            return ret;
        }
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* UART                                                                       */
/* -------------------------------------------------------------------------- */

static status_t
setup_uart(
    struct vm_t *vm, uint64_t uart)
{
    status_t ret = SUCCESS;

    if (uart != 0) {
        ret = __domain_op__set_uart(vm->domainid, uart);
        if (ret != SUCCESS) {
            BFDEBUG("donate_page: __domain_op__set_uart failed\n");
        }
    }

    return ret;
}

static status_t
setup_pt_uart(
    struct vm_t *vm, uint64_t uart)
{
    status_t ret = SUCCESS;

    if (uart != 0) {
        ret = __domain_op__set_pt_uart(vm->domainid, uart);
        if (ret != SUCCESS) {
            BFDEBUG("donate_page: __domain_op__set_pt_uart failed\n");
        }
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* GPA Functions                                                              */
/* -------------------------------------------------------------------------- */

static status_t
setup_xen_start_info(struct vm_t *vm)
{
    status_t ret;

    vm->xen_start_info = bfalloc_page(struct hvm_start_info);
    if (vm->xen_start_info == 0) {
        BFDEBUG("setup_xen_start_info: failed to alloc start into page\n");
        return FAILURE;
    }

    vm->xen_start_info->magic = XEN_HVM_START_MAGIC_VALUE;
    vm->xen_start_info->version = 0;
    vm->xen_start_info->cmdline_paddr = XEN_COMMAND_LINE_PAGE_GPA;
    vm->xen_start_info->rsdp_paddr = ACPI_RSDP_GPA;

    ret = donate_page(vm, vm->xen_start_info, XEN_START_INFO_PAGE_GPA, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_xen_start_info: donate failed\n");
        return ret;
    }

    return ret;
}

static status_t
setup_xen_cmdline(struct vm_t *vm, struct create_from_elf_args *args)
{
    status_t ret;

    if (args->cmdl_size >= BAREFLANK_PAGE_SIZE) {
        BFDEBUG("setup_xen_cmdline: cmdl must be smaller than a page\n");
        return FAILURE;
    }

    vm->xen_cmdl = bfalloc_page(char);
    if (vm->xen_cmdl == 0) {
        BFDEBUG("setup_xen_cmdline: failed to alloc cmdl page\n");
        return FAILURE;
    }

    platform_memcpy(vm->xen_cmdl, args->cmdl, args->cmdl_size);

    ret = donate_page(vm, vm->xen_cmdl, XEN_COMMAND_LINE_PAGE_GPA, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_xen_cmdline: donate failed\n");
        return ret;
    }

    return SUCCESS;
}

static status_t
setup_xen_console(struct vm_t *vm)
{
    status_t ret;

    vm->xen_console = bfalloc_page(void);
    if (vm->xen_console == 0) {
        BFDEBUG("setup_xen_console: failed to alloc console page\n");
        return FAILURE;
    }

    ret = donate_page(vm, vm->xen_console, XEN_CONSOLE_PAGE_GPA, MAP_RW);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_xen_console: donate failed\n");
        return ret;
    }

    return ret;
}

static status_t
setup_bios_ram(struct vm_t *vm)
{
    status_t ret;

    vm->bios_ram = bfalloc_buffer(void, BIOS_RAM_SIZE);
    if (vm->bios_ram == 0) {
        BFDEBUG("setup_bios_ram: failed to alloc bios ram\n");
        return FAILURE;
    }

    ret = donate_buffer(vm, vm->bios_ram, BIOS_RAM_ADDR, BIOS_RAM_SIZE, MAP_RWE);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_bios_ram: donate failed\n");
        return ret;
    }

    return ret;
}

static status_t
setup_reserved_free(struct vm_t *vm)
{
    status_t ret;

    vm->zero_page = bfalloc_page(void);
    if (vm->zero_page == 0) {
        BFDEBUG("setup_reserved_free: failed to alloc zero page\n");
        return FAILURE;
    }

    ret = donate_page_to_page_range(
        vm, vm->zero_page, RESERVED1_ADRR, RESERVED1_SIZE, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_reserved_free: donate failed\n");
        return ret;
    }

    ret = donate_page_to_page_range(
        vm, vm->zero_page, RESERVED2_ADRR, RESERVED2_ADRR, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFDEBUG("setup_reserved_free: donate failed\n");
        return ret;
    }

    return ret;
}

static status_t
setup_kernel(struct vm_t *vm, struct create_from_elf_args *args)
{
    status_t ret;

    vm->bfelf_binary.file = args->file;
    vm->bfelf_binary.file_size = args->file_size;
    vm->bfelf_binary.exec = 0;
    vm->bfelf_binary.exec_size = args->size;
    vm->bfelf_binary.start_addr = (void *)START_ADDR;

    ret = bfelf_load(&vm->bfelf_binary, 1, 0, 0, &vm->bfelf_loader);
    if (ret != BF_SUCCESS) {
        return ret;
    }

    ret = donate_buffer(
        vm, vm->bfelf_binary.exec, START_ADDR, args->size, MAP_RWE);
    if (ret != SUCCESS) {
        return ret;
    }

    return ret;
}

// TODO:
//
// We need to move the ACPI and Initial GDT/IDT/TSS to this driver and
// out of the hypervisor as these should be resources managed by the
// builder, not the hypervisor.
//

/* -------------------------------------------------------------------------- */
/* Initial Register State                                                     */
/* -------------------------------------------------------------------------- */

static status_t
get_phys32_entry(struct vm_t *vm, uint32_t *entry)
{
    uint64_t i;
    const uint32_t *hay;
    const struct bfelf_shdr *shdr;

    const uint32_t needle[5] = {
        0x4U, 0x8U, 0x12U, 0x006e6558U, 0x0
    };

    shdr = vm->bfelf_binary.ef.notes;
    if (!shdr) {
        BFDEBUG("get_entry: no notes section\n");
        return FAILURE;
    }

    hay = (uint32_t *)(vm->bfelf_binary.file + shdr->sh_offset);

    for (i = 0; i < shdr->sh_size - sizeof(needle); i++) {
        if (hay[i + 0] == needle[0] &&
            hay[i + 1] == needle[1] &&
            hay[i + 2] == needle[2] &&
            hay[i + 3] == needle[3]
        ) {
            *entry = hay[i + 4];
            return SUCCESS;
        }
    }

    return FAILURE;
}

static status_t
setup_entry(struct vm_t *vm)
{
    status_t ret;

    ret = get_phys32_entry(vm, &vm->entry);
    if (ret != SUCCESS) {
        BFDEBUG("setup_entry: failed to locate pvh_start_xen\n");
        return ret;
    }

    ret = __domain_op__set_entry(vm->domainid, vm->entry);
    if (ret != SUCCESS) {
        BFDEBUG("setup_entry: __domain_op__set_entry failed\n");
    }

    return ret;
}

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

int64_t
common_create_from_elf(
    struct vm_t *vm, struct create_from_elf_args *args)
{
    status_t ret;

    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return HYPERVISOR_NOT_LOADED;
    }

    vm->domainid = __domain_op__create_domain();
    if (vm->domainid == INVALID_DOMAINID) {
        BFDEBUG("__domain_op__create_domain failed\n");
        return CREATE_FROM_ELF_FAILED;
    }

    __domain_op__set_ndvm_status(vm->domainid, args->is_ndvm);
    if (args->is_ndvm) {
        __domain_op__set_ndvm_bus(vm->domainid, args->bus);
    }

    ret = setup_e820_map(vm, args->size);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_xen_start_info(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_xen_cmdline(vm, args);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_xen_console(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_bios_ram(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_reserved_free(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_kernel(vm, args);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_entry(vm);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_uart(vm, args->uart);
    if (ret != SUCCESS) {
        return ret;
    }

    ret = setup_pt_uart(vm, args->pt_uart);
    if (ret != SUCCESS) {
        return ret;
    }

    args->domainid = vm->domainid;
    return BF_SUCCESS;
}

int64_t
common_destroy(struct vm_t *vm)
{
    status_t ret;

    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return HYPERVISOR_NOT_LOADED;
    }

    ret = __domain_op__destroy_domain(vm->domainid);
    if (ret != SUCCESS) {
        BFDEBUG("__domain_op__destroy_domain failed\n");
        return FAILURE;
    }

    platform_free_rw(vm->bfelf_binary.exec, vm->bfelf_binary.exec_size);
    platform_free_rw(vm->xen_start_info, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->xen_cmdl, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->xen_console, BAREFLANK_PAGE_SIZE);
    platform_free_rw(vm->bios_ram, 0xE8000);
    platform_free_rw(vm->zero_page, BAREFLANK_PAGE_SIZE);

    platform_memset(vm, 0, sizeof(struct vm_t));
    return BF_SUCCESS;
}
