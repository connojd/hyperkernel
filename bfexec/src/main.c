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

#include <bfaffinity.h>
#include <bfelf_loader.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <sys/mman.h>

#include <hypercall.h>
#include <gpa_layout.h>

#include <hve/arch/intel_x64/xen/public/xen.h>
#include <hve/arch/intel_x64/xen/public/elfnote.h>

#include "xen/start_info.h"
#include "xen/elf_note.h"

// Notes:
//
// - Currently on one vCPU is supported. This code is written using threading
//   so adding support for more than one vCPU should be simple once the
//   hyperkernel supports this. Just create more vCPU threads
//
// - Currently this code doesn't handle when the VM wishes to go to sleep
//   by calling "hlt". Once the hyperkernel supports this, we will need to
//   add support for this application to wait on a kernel event. The only
//   way to wake up from "hlt" is to interrupt the CPU. Such and interrupt
//   will either have to come from an external interrupt, or it will have to
//   come from a timer interrupt. Either way, execution doesn't need to
//   continue until an event occurs, which we will have to add support for.
//
// - Currently, we do not support VMCS migration, which means we have to
//   set the affinity of bfexec. At some point, we need to implement
//   VMCS migration so that we can support executing from any core, at any
//   time.
//

#define alloc_page() platform_memset(platform_alloc_rwe(0x1000), 0, 0x1000);
#define alloc_buffer(sz) platform_memset(platform_alloc_rwe((sz)), 0, (sz));

/* -------------------------------------------------------------------------- */
/* VM                                                                         */
/* -------------------------------------------------------------------------- */

struct vm_t {
    struct crt_info_t crt_info;
    struct bfelf_loader_t bfelf_loader;
    struct bfelf_binary_t bfelf_binary;

    void *entry;

    uint64_t domainid;
    uint64_t vcpuid;

    FILE *file;
    pthread_t run_thread;
} g_vm;

/* -------------------------------------------------------------------------- */
/* Ack                                                                        */
/* -------------------------------------------------------------------------- */

uint32_t _cpuid_eax(uint32_t val) NOEXCEPT;

/* -------------------------------------------------------------------------- */
/* Signal Handling                                                            */
/* -------------------------------------------------------------------------- */

#include <signal.h>

void
kill_signal_handler(void)
{
    status_t ret;

    BFINFO("\n");
    BFINFO("\n");
    BFINFO("killing VM: %" PRId64 "\n", g_vm.domainid);

    ret = __vcpu_op__hlt_vcpu(g_vm.vcpuid);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__hlt_vcpu failed\n");
        return;
    }

    return;
}

void
sig_handler(int sig)
{
    bfignored(sig);
    kill_signal_handler();
    return;
}

void
setup_kill_signal_handler(void)
{
    signal(SIGINT, sig_handler);
    signal(SIGQUIT, sig_handler);
    signal(SIGTERM, sig_handler);
}

/* -------------------------------------------------------------------------- */
/* Domain Functions                                                           */
/* -------------------------------------------------------------------------- */

status_t
domain_op__create_domain(void)
{
    g_vm.domainid = __domain_op__create_domain();
    if (g_vm.domainid == INVALID_DOMAINID) {
        BFALERT("__domain_op__create_domain failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
domain_op__destroy_domain(void)
{
    status_t ret;

    ret = __domain_op__destroy_domain(g_vm.domainid);
    if (ret != SUCCESS) {
        BFALERT("__domain_op__destroy_domain failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
domain_op__map_gpa(uint64_t gva, uint64_t gpa, uint64_t type)
{
    status_t ret;

    ret = __domain_op__map_gpa(g_vm.domainid, gva, gpa, type);
    if (ret != SUCCESS) {
        BFALERT("__domain_op__map_gpa failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
domain_op__map_gpa_single_gva(
    uint64_t gva, uint64_t gpa, uint64_t size, uint64_t type)
{
    uint64_t index;

    for (index = 0; index < size; index += 0x1000) {
        status_t ret = domain_op__map_gpa(
            gva, gpa + index, type
        );

        if (ret != SUCCESS) {
            BFALERT("map_mem failed\n");
            return FAILURE;
        }
    }

    return SUCCESS;
}


status_t
domain_op__map_buffer(
    uint64_t gva, uint64_t gpa, uint64_t size, uint64_t type)
{
    uint64_t index;

    for (index = 0; index < size; index += 0x1000) {
        status_t ret = domain_op__map_gpa(
            gva + index, gpa + index, type
        );

        if (ret != SUCCESS) {
            BFALERT("map_mem failed\n");
            return FAILURE;
        }
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* vCPU Functions                                                             */
/* -------------------------------------------------------------------------- */

static const struct bfelf_shdr *
find_note_section(const struct bfelf_file_t *ef)
{
    int i;
    for (i = 0; i < ef->ehdr->e_shnum; i++) {
        const struct bfelf_shdr *shdr = &(ef->shdrtab[i]);
        const char *name = &ef->shstrtab[shdr->sh_name];
        if (strncmp(name, ".notes", 7)) {
            continue;
        }
        break;
    }

    if (i == ef->ehdr->e_shnum) {
        return NULL;
    }

    const struct bfelf_shdr *shdr = &(ef->shdrtab[i]);
    if ((shdr->sh_size & 0x3) != 0) {
        BFALERT("vmlinux: invalid .notes section size: %d\n", shdr->sh_size);
        return NULL;
    }

    return shdr;
}

static status_t
set_vm_entry(const struct bfelf_binary_t *bin, uintptr_t *entry)
{
    if (!bin) {
        return FAILURE;
    }

    const struct bfelf_file_t *ef = (const struct bfelf_file_t *)&bin->ef;
    if (!ef) {
        return FAILURE;
    }

    const struct bfelf_shdr *shdr = find_note_section(ef);
    if (!shdr) {
        return FAILURE;
    }

    const uint32_t *hay = (const uint32_t *)(bin->file + shdr->sh_offset);
    const uint64_t dwords = shdr->sh_size / 4;
    const uint32_t needle[4] = {
        0x4U, /* namesz */
        0x8U, /* descsz */
        0x12U, /* type */
        0x006e6558U /* "Xen\0" */
    };

    for (uint64_t i = 0; (i + 5) < dwords; i++) {
        if (hay[i] != needle[0]) {
            continue;
        }
        if (hay[i + 1] != needle[1]) {
            i++;
            continue;
        }
        if (hay[i + 2] != needle[2]) {
            i += 2;
            continue;
        }
        if (hay[i + 3] != needle[3]) {
            i += 3;
            continue;
        }

        uint64_t *addr = (uint64_t *)&hay[i + 4];
        *entry = *addr;

        return SUCCESS;
    }

    return FAILURE;
}

status_t
vcpu_op__create_vcpu(void)
{
    status_t ret;

    g_vm.vcpuid = __vcpu_op__create_vcpu(g_vm.domainid);
    if (g_vm.vcpuid == INVALID_VCPUID) {
        BFALERT("__vcpu_op__create_vcpu failed\n");
        return FAILURE;
    }

    ret = set_vm_entry(&g_vm.bfelf_binary, (uintptr_t *)&g_vm.entry);
    if (ret != BF_SUCCESS) {
        BFALERT("set_vm_entry: 0x%016" PRIx64 "\n", ret);
        return FAILURE;
    }

    ret = __vcpu_op__set_rip(g_vm.vcpuid, (uint64_t)g_vm.entry);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__set_rip failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

static inline uint64_t vcpu_run_code(status_t s)
{ return (uint64_t)s & ~VCPU_OP__SLEEP_USEC; }

static inline uint64_t vcpu_sleep_usec(status_t s)
{ return ((uint64_t)s & VCPU_OP__SLEEP_USEC) >> 16U; }

#include <time.h>
int usleep(int microseconds)
{
   struct timespec req, rem;

   if(microseconds > 1000000) {
        req.tv_sec = microseconds / 1000000;
        req.tv_nsec = (microseconds % 1000000) * 1000;
   }
   else {
        req.tv_sec = 0;
        req.tv_nsec = microseconds * 1000;
   }

   return nanosleep(&req , &rem);
}

void *
vcpu_op__run_vcpu(void *arg)
{
    status_t ret;
    bfignored(arg);

    while (1) {
        ret = __vcpu_op__run_vcpu(g_vm.vcpuid);
        switch(vcpu_run_code(ret)) {
            case SUCCESS:
                return 0;

            case FAILURE:
                BFALERT("__vcpu_op__run_vcpu failed\n");
                exit(-1);
                return 0;

            case VCPU_OP__RUN_CONTINUE:
                continue;

            case VCPU_OP__RUN_SLEEP:
                usleep(vcpu_sleep_usec(ret));
                continue;

            default:
                BFALERT("unknown run_vcpu return code: %d\n", ret);
                return 0;
        }
    }
}

status_t
vcpu_op__destroy_vcpu(void)
{
    status_t ret;

    ret = __vcpu_op__destroy_vcpu(g_vm.vcpuid);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__destroy_vcpu failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Threading                                                                  */
/* -------------------------------------------------------------------------- */

#include <pthread.h>

void
start_run_thread()
{ pthread_create(&g_vm.run_thread, 0, vcpu_op__run_vcpu, 0); }

/* -------------------------------------------------------------------------- */
/* Memory Layout                                                              */
/* -------------------------------------------------------------------------- */

/**
 *       0x0 +----------------------+ ---
 *           | Unusable             |  | Unusable
 *    0x1000 +----------------------+ ---
 *           | Initial GDT          |  |
 *    0x2000 +----------------------+  |
 *           | Initial IDT          |  |
 *    0x3000 +----------------------+  |
 *           | Initial TSS          |  | Reserved
 *    0x4000 +----------------------+  |
 *           | Xen Start Info       |  |
 *    0x5000 +----------------------+  |
 *           | Xen CMD Line         |  |
 *    0x6000 +----------------------+ ---
 *           | Xen shared Info Page |  | RAM
 *    0x7000 +----------------------+ ---
 *           | Unusable             |  | Unusable
 *   0xE0000 +----------------------+ ---
 *           | ACPI                 |  | Reserved
 *   0xF0000 +----------------------+ ---
 *           | Local APIC           |  | Reserved
 *  0x100000 +----------------------+ ---
 *           | Unusable             |  | Unusable
 * 0x1000000 +----------------------+ ---
 *           | Linux ELF (Xen PVH)  |  |
 *       XXX +----------------------+  | RAM
 *           | Usable RAM           |  |
 * 0x9000000 +----------------------+ ---
 */

typedef union {
    hvm_start_info start_info;
    char pad[0x1000];
} reserved_4000_t;

typedef struct {
    char cmdline[0x1000];
} reserved_5000_t;

typedef struct {
    char shared_info_page[0x1000];
} reserved_6000_t;

typedef struct {
    char console[0x1000];
} reserved_7000_t;

typedef struct {
    char store[0x1000];
} reserved_8000_t;

#ifndef REAL_MODE_SIZE
#define REAL_MODE_SIZE (6 * 0x1000)
#endif

typedef struct {
    char rm_trampoline[REAL_MODE_SIZE];
} reserved_A000_t;

reserved_4000_t *g_reserved_4000 = 0;   /* Xen start info */
reserved_5000_t *g_reserved_5000 = 0;   /* Xen cmdline */
reserved_6000_t *g_reserved_6000 = 0;   /* Xen shared info page */
reserved_7000_t *g_reserved_7000 = 0;   /* Xen console */
reserved_8000_t *g_reserved_8000 = 0;   /* Xen store */
//reserved_9000_t *g_reserved_9000 = 0;   /* 4K hole for DSDT */
reserved_A000_t *g_reserved_A000 = 0;   /* Real-mode trampoline */

// TODO: this should be a setting that is filled in from the command line.
uint64_t g_ram_addr = 0x1000000;
uint64_t g_ram_size = 128 << 20;

void *g_zero_page;

status_t
setup_e820_map()
{
    status_t ret;

    ret = __domain_op__add_e820_entry(
        g_vm.domainid,
        0,
        0x1000,
        XEN_HVM_MEMMAP_TYPE_UNUSABLE
    );

    if (ret != SUCCESS) {
        BFALERT("__domain_op__add_e820_entry failed\n");
        return FAILURE;
    }

    ret = __domain_op__add_e820_entry(
        g_vm.domainid,
        0x1000,
        0x5000,
        XEN_HVM_MEMMAP_TYPE_RESERVED
    );

    if (ret != SUCCESS) {
        BFALERT("__domain_op__add_e820_entry failed\n");
        return FAILURE;
    }

    ret = __domain_op__add_e820_entry(
        g_vm.domainid,
        0x6000,
        0x1000,
        XEN_HVM_MEMMAP_TYPE_RAM
    );

    if (ret != SUCCESS) {
        BFALERT("__domain_op__add_e820_entry failed\n");
        return FAILURE;
    }

    ret = __domain_op__add_e820_entry(
        g_vm.domainid,
        0x7000,
        0x1000,
        XEN_HVM_MEMMAP_TYPE_RAM
    );

    if (ret != SUCCESS) {
        BFALERT("__domain_op__add_e820_entry failed\n");
        return FAILURE;
    }

    ret = __domain_op__add_e820_entry(
        g_vm.domainid,
        0x8000,
        0x1000,
        XEN_HVM_MEMMAP_TYPE_RAM
    );

    if (ret != SUCCESS) {
        BFALERT("__domain_op__add_e820_entry failed\n");
        return FAILURE;
    }

    // ret = __domain_op__add_e820_entry(
    //     g_vm.domainid,
    //     0x9000,
    //     0x1000,
    //     XEN_HVM_MEMMAP_TYPE_RAM
    // );

    // if (ret != SUCCESS) {
    //     BFALERT("__domain_op__add_e820_entry failed\n");
    //     return FAILURE;
    // }

    ret = __domain_op__add_e820_entry(
        g_vm.domainid,
        0xA000,
        REAL_MODE_SIZE,
        XEN_HVM_MEMMAP_TYPE_RAM
    );

    if (ret != SUCCESS) {
        BFALERT("__domain_op__add_e820_entry failed\n");
        return FAILURE;
    }

    ret = __domain_op__add_e820_entry(
        g_vm.domainid,
        0xA000 + REAL_MODE_SIZE,
        g_ram_addr - (0xA000 + REAL_MODE_SIZE),
        XEN_HVM_MEMMAP_TYPE_UNUSABLE
    );

    if (ret != SUCCESS) {
        BFALERT("__domain_op__add_e820_entry failed\n");
        return FAILURE;
    }

    ret = __domain_op__add_e820_entry(
        g_vm.domainid,
        g_ram_addr,
        g_ram_size,
        XEN_HVM_MEMMAP_TYPE_RAM
    );

    if (ret != SUCCESS) {
        BFALERT("__domain_op__add_e820_entry failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* ELF File Functions                                                         */
/* -------------------------------------------------------------------------- */

status_t
binary_read(const char *filename)
{
    char *data;
    uint64_t size;

    g_vm.file = fopen(filename, "rb");
    if (g_vm.file == 0) {
        BFALERT("failed to open: %s\n", filename);
        return FAILURE;
    }

    if (fseek(g_vm.file, 0, SEEK_END) != 0) {
        BFALERT("fseek failed: %s\n", strerror(errno));
        return FAILURE;
    }

    size = (uint64_t)ftell(g_vm.file);
    if (size == (uint64_t)-1) {
        BFALERT("ftell failed: %s\n", strerror(errno));
        return FAILURE;
    }

    if (fseek(g_vm.file, 0, SEEK_SET) != 0) {
        BFALERT("fseek failed: %s\n", strerror(errno));
        return FAILURE;
    }

    data = (char *)platform_alloc_rwe(size);
    if (data == 0) {
        BFALERT("malloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    if (fread(data, 1, size, g_vm.file) != size) {
        BFALERT("fread failed to read entire file: %s\n", strerror(errno));
        return FAILURE;
    }

    g_vm.bfelf_binary.file = data;
    g_vm.bfelf_binary.file_size = size;

    return SUCCESS;
}

status_t
binary_load(void)
{
    status_t ret;
    uint64_t gva;

    /**
     * NOTE:
     *
     * For PIE, we need to provide an address (g_ram_addr). This will be
     * overwritten if the binary is non-PIE (i.e. static), which is why we
     * have to get the start address again after we call bfelf_load
     *
     * NOTE:
     *
     * This is where we allocate RAM. We let the ELF loader allocate RAM for
     * us, and fill in the first part of RAM with the ELF file. The ELF
     * loader will ensure RAM is zero'd out, and will ensure the RAM is page
     * aligned, which is needed for mapping.
    */

    g_vm.bfelf_binary.exec_size = g_ram_size;
    g_vm.bfelf_binary.start_addr = (void *)g_ram_addr;

    ret = bfelf_load(&g_vm.bfelf_binary, 1, &g_vm.entry, &g_vm.crt_info, &g_vm.bfelf_loader);
    if (ret != BF_SUCCESS) {
        BFALERT("bfelf_load: 0x%016" PRIx64 "\n", ret);
        return FAILURE;
    }

    gva = (uint64_t)g_vm.bfelf_binary.exec;
    g_ram_addr = (uint64_t)g_vm.bfelf_binary.start_addr;

    ret = domain_op__map_buffer(gva, g_ram_addr, g_ram_size, MAP_RWE);
    if (ret != SUCCESS) {
        BFALERT("bfelf_load: 0x%016" PRIx64 "\n", ret);
        return FAILURE;
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Xen Info                                                                   */
/* -------------------------------------------------------------------------- */

status_t
setup_xen_start_info()
{
    status_t ret;

    g_reserved_4000 = (reserved_4000_t *)alloc_page();
    if (g_reserved_4000 == 0) {
        BFALERT("g_reserved_4000 alloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    g_reserved_4000->start_info.magic = XEN_HVM_START_MAGIC_VALUE;
    g_reserved_4000->start_info.version = 0;
    g_reserved_4000->start_info.cmdline_paddr = 0x5000;
    g_reserved_4000->start_info.rsdp_paddr = ACPI_RSDP_GPA;

    ret = domain_op__map_gpa((uint64_t)g_reserved_4000, 0x4000, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFALERT("__domain_op__map_gpa failed\n");
        return FAILURE;
    }

    ret = __vcpu_op__set_rbx(g_vm.vcpuid, 0x4000);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__set_rbx failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
setup_xen_cmdline()
{
    status_t ret;
    const char *cmdline = "console=uart,io,0x3F8,115200n8 pci=earlydump,lastbus=2,nocrs r8169.debug=16 init=/hello";

    /**
     * TODO:
     * - We need to use a "--" similar to gdb to get the command line options
     * from the user so that they can be added here
     */

    g_reserved_5000 = (reserved_5000_t *)alloc_page();
    if (g_reserved_5000 == 0) {
        BFALERT("g_reserved_5000 alloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    ret = domain_op__map_gpa((uint64_t)g_reserved_5000, 0x5000, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFALERT("__domain_op__map_gpa failed\n");
        return FAILURE;
    }

    strncpy(g_reserved_5000->cmdline, cmdline, 0x1000);
    return SUCCESS;
}

status_t
setup_xen_shared_info_page()
{
    status_t ret;

    g_reserved_6000 = (reserved_6000_t *)alloc_page();
    if (g_reserved_6000 == 0) {
        BFALERT("g_reserved_6000 alloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    memset((char *)g_reserved_6000, 0, 0x1000);
    ret = domain_op__map_gpa((uint64_t)g_reserved_6000, 0x6000, MAP_RW);
    if (ret != BF_SUCCESS) {
        BFALERT("__domain_op__map_gpa failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
setup_xen_console()
{
    status_t ret;

    g_reserved_7000 = (reserved_7000_t *)alloc_page();
    if (g_reserved_7000 == 0) {
        BFALERT("g_reserved_7000 alloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    ret = domain_op__map_gpa((uint64_t)g_reserved_7000, 0x7000, MAP_RW);
    if (ret != BF_SUCCESS) {
        BFALERT("__domain_op__map_gpa failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
setup_xen_store()
{
    status_t ret;

    g_reserved_8000 = (reserved_8000_t *)alloc_page();
    if (g_reserved_8000 == 0) {
        BFALERT("g_reserved_8000 alloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    ret = domain_op__map_gpa((uint64_t)g_reserved_8000, 0x8000, MAP_RW);
    if (ret != BF_SUCCESS) {
        BFALERT("__domain_op__map_gpa failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
setup_rm_trampoline()
{
    status_t ret;
    uint32_t size = REAL_MODE_SIZE;

    g_reserved_A000 = (reserved_A000_t *)alloc_buffer(size);
    if (g_reserved_A000 == 0) {
        BFALERT("g_reserved_A000 alloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    ret = domain_op__map_buffer((uint64_t)g_reserved_A000, 0xA000, size, MAP_RWE);
    if (ret != BF_SUCCESS) {
        BFALERT("__domain_op__map_buffer failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
setup_xen_disabled()
{
    status_t ret;

    /**
     * Note:
     *
     * The following disables specific portions of memory by mapping them to
     * a zero page. Specifically, the guest might attempt to access these
     * pages expecting to find something, which they will not. If we don't map
     * these, the guest will attempt to access them anyways and crash from an
     * EPT violation
     */

    g_zero_page = alloc_page();
    if (g_zero_page == 0) {
        BFALERT("g_zero_page alloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    /* Zero Page */
    ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0x0, 0x1000, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFALERT("domain_op__map_gpa_single_gva failed\n");
        return FAILURE;
    }

    /* Disable DMI */
    ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0xF0000, 0x10000, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFALERT("domain_op__map_gpa_single_gva failed\n");
        return FAILURE;
    }

    /* Disable Video BIOS region */
    ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0xC0000, 0x10000, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFALERT("domain_op__map_gpa_single_gva failed\n");
        return FAILURE;
    }

    /* ROMs */
    ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0xD0000, 0x10000, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFALERT("domain_op__map_gpa_single_gva failed\n");
        return FAILURE;
    }

    /* ROMs */
    ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0xE4000, 0x10000 - 0x4000, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFALERT("domain_op__map_gpa_single_gva failed\n");
        return FAILURE;
    }

    // TODO:
    //
    // To support MP, we will have to remove the following and provide an
    // actual MP table that mimics the ACPI tables as both are required.
    //
    // https://elixir.bootlin.com/linux/v3.7/source/arch/x86/kernel/mpparse.c#L604
    //

    /* MP Table */
    ret = domain_op__map_gpa_single_gva((uint64_t)g_zero_page, 0x9F000, 0x1000, MAP_RO);
    if (ret != BF_SUCCESS) {
        BFALERT("domain_op__map_gpa_single_gva failed\n");
        return FAILURE;
    }

    return SUCCESS;
}


/* -------------------------------------------------------------------------- */
/* Main                                                                       */
/* -------------------------------------------------------------------------- */

int
main(int argc, const char *argv[])
{
    status_t ret;
    memset(&g_vm, 0, sizeof(g_vm));

    if (argc != 2) {
        BFALERT("invalid number of arguments\n");
        return EXIT_FAILURE;
    }

    if (_cpuid_eax(0xBF00) != 0xBF01) {
        return EXIT_FAILURE;
    }

    /**
     * Note that affinity *must* be set before any VM-bound resources are
     * allocated. Failure to do so can (and will) result in the kernel mapping
     * in memory on a core that is different from the one bareflank maps on. In
     * this case, bareflank's mmap will walk an invalid CR3, resulting in (at
     * best) an EPT violation when the guest starts to run.
     */
    set_affinity(0);

    setup_kill_signal_handler();
    platform_init();

    ret = domain_op__create_domain();
    if (ret != SUCCESS) {
        BFALERT("create_domain failed\n");
        return EXIT_FAILURE;
    }

    ret = setup_e820_map();
    if (ret != SUCCESS) {
        BFALERT("setup_e820_map failed\n");
        goto CLEANUP_VCPU;
    }

    ret = binary_read(argv[1]);
    if (ret != SUCCESS) {
        BFALERT("read_binary failed\n");
        goto CLEANUP_DOMAIN;
    }

    ret = binary_load();
    if (ret != SUCCESS) {
        BFALERT("load_binary failed\n");
        goto CLEANUP_DOMAIN;
    }

    ret = set_vm_entry(&g_vm.bfelf_binary, (uintptr_t *)&g_vm.entry);
    if (ret != SUCCESS) {
        BFALERT("set_vm_entry failed\n");
        return EXIT_FAILURE;
    }

    ret = vcpu_op__create_vcpu();
    if (ret != SUCCESS) {
        BFALERT("create_vcpu failed\n");
        goto CLEANUP_DOMAIN;
    }

    ret = setup_xen_start_info();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_start_info failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_cmdline();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_cmdline failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_shared_info_page();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_shared_info_page failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_console();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_console failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_store();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_store failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_rm_trampoline();
    if (ret != SUCCESS) {
        BFALERT("setup_rm_trampoline failed\n");
        goto CLEANUP_VCPU;
    }

    ret = setup_xen_disabled();
    if (ret != SUCCESS) {
        BFALERT("setup_xen_disabled failed\n");
        goto CLEANUP_VCPU;
    }

    start_run_thread();
    pthread_join(g_vm.run_thread, 0);

CLEANUP_VCPU:

    ret = vcpu_op__destroy_vcpu();
    if (ret != SUCCESS) {
        BFALERT("destroy_vcpu failed\n");
    }

CLEANUP_DOMAIN:

    ret = domain_op__destroy_domain();
    if (ret != SUCCESS) {
        BFALERT("destroy_domain failed\n");
    }

    return EXIT_SUCCESS;
}
