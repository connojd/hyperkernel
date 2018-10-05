//
// Bareflank Hyperkernel
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <bfaffinity.h>

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <hypercall.h>
#include <bfelf_loader.h>

#include <sys/mman.h>

struct vm_t
{
    struct crt_info_t crt_info;
    struct bfelf_loader_t bfelf_loader;
    struct bfelf_binary_t bfelf_binary;

    void *entry;
    void *stack;

    uint64_t domainid;
    uint64_t vcpuid;

    FILE *file;
    void *stack_buffer;
};

#define STACK_ADDR 0x200000
#define ENTRY_ADDR 0x400000

// -----------------------------------------------------------------------------
// Ack
// -----------------------------------------------------------------------------

uint32_t _cpuid_eax(uint32_t val) NOEXCEPT;

inline uint64_t
ack()
{ return _cpuid_eax(0xBF00); }

/* -------------------------------------------------------------------------- */
/* ELF File Functions                                                         */
/* -------------------------------------------------------------------------- */

status_t
read_binary(struct vm_t *vm, const char *filename)
{
    char *data;
    uint64_t size;

    vm->file = fopen(filename, "rb");
    if (vm->file == 0) {
        BFALERT("failed to open: %s\n", filename);
        return FAILURE;
    }

    if (fseek(vm->file, 0, SEEK_END) != 0) {
        BFALERT("fseek failed: %s\n", strerror(errno));
        return FAILURE;
    }

    size = (uint64_t)ftell(vm->file);
    if (size == (uint64_t)-1) {
        BFALERT("ftell failed: %s\n", strerror(errno));
        return FAILURE;
    }

    if (fseek(vm->file, 0, SEEK_SET) != 0) {
        BFALERT("fseek failed: %s\n", strerror(errno));
        return FAILURE;
    }

    data = (char *)aligned_alloc(0x1000, size);
    if (data == 0) {
        BFALERT("malloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    if (fread(data, 1, size, vm->file) != size) {
        BFALERT("fread failed to read entire file: %s\n", strerror(errno));
        return FAILURE;
    }

    vm->bfelf_binary.file = data;
    vm->bfelf_binary.file_size = size;

    vm->stack = (void *)(STACK_ADDR + STACK_SIZE - 1);
    vm->bfelf_binary.exec_virt = (void *)ENTRY_ADDR;

    return SUCCESS;
}

status_t
load_binary(struct vm_t *vm)
{
    status_t ret;
    uint64_t index;

    ret = bfelf_load(&vm->bfelf_binary, 1, &vm->entry, &vm->crt_info, &vm->bfelf_loader);
    if (ret != BF_SUCCESS) {
        BFALERT("bfelf_load: 0x%016" PRIx64 "\n", ret);
        return FAILURE;
    }

    vm->stack_buffer = platform_alloc_rw(STACK_SIZE);
    if (vm->stack_buffer == 0) {
        BFALERT("malloc failed: %s\n", strerror(errno));
        return FAILURE;
    }

    if (mlock(vm->bfelf_binary.exec, vm->bfelf_binary.exec_size) != 0) {
        BFALERT("mlock failed: %s\n", strerror(errno));
        return FAILURE;
    }

    if (mlock(vm->stack_buffer, STACK_SIZE) != 0) {
        BFALERT("mlock failed: %s\n", strerror(errno));
        return FAILURE;
    }

    for (index = 0; index < STACK_SIZE; index += 0x1000) {
        ret = __domain_op__map_md(
            vm->domainid, (uint64_t)vm->stack_buffer + index, STACK_ADDR + index
        );

        if (ret != SUCCESS) {
            BFALERT("__domain_op__map_md failed\n");
            return FAILURE;
        }
    }

    for (index = 0; index < vm->bfelf_binary.exec_size; index += 0x1000) {
        ret = __domain_op__map_md(
            vm->domainid, (uint64_t)vm->bfelf_binary.exec + index, ENTRY_ADDR + index
        );

        if (ret != SUCCESS) {
            BFALERT("__domain_op__map_md failed\n");
            return FAILURE;
        }
    }

    ret = __domain_op__map_commit(vm->domainid);
    if (ret != SUCCESS) {
        BFALERT("__domain_op__map_commit failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* Domain Functions                                                           */
/* -------------------------------------------------------------------------- */

status_t
create_domain(struct vm_t *vm)
{
    vm->domainid = __domain_op__create_domain();
    if (vm->domainid == INVALID_DOMAINID) {
        BFALERT("__domain_op__create_domain failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
destroy_domain(struct vm_t *vm)
{
    status_t ret;

    ret = __domain_op__destroy_domain(vm->domainid);
    if (ret != SUCCESS) {
        BFALERT("__domain_op__destroy_domain failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

/* -------------------------------------------------------------------------- */
/* vCPU Functions                                                             */
/* -------------------------------------------------------------------------- */

status_t
create_vcpu(struct vm_t *vm)
{
    status_t ret;

    vm->vcpuid = __vcpu_op__create_vcpu(vm->domainid);
    if (vm->vcpuid == INVALID_VCPUID) {
        BFALERT("__vcpu_op__create_vcpu failed\n");
        return FAILURE;
    }

    ret = __vcpu_op__set_entry(vm->vcpuid, (uint64_t)vm->entry);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__set_entry failed\n");
        return FAILURE;
    }

    ret = __vcpu_op__set_stack(vm->vcpuid, (uint64_t)vm->stack);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__set_stack failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
run_vcpu(struct vm_t *vm)
{
    status_t ret;

    ret = __vcpu_op__run_vcpu(vm->vcpuid);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__run_vcpu failed\n");
        return FAILURE;
    }

    return SUCCESS;
}

status_t
destroy_vcpu(struct vm_t *vm)
{
    status_t ret;

    ret = __vcpu_op__destroy_vcpu(vm->vcpuid);
    if (ret != SUCCESS) {
        BFALERT("__vcpu_op__destroy_vcpu failed\n");
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
    bfignored(argc);

    struct vm_t vm;
    memset(&vm, 0, sizeof(vm));

    if (ack() == 0) {
        return EXIT_FAILURE;
    }

    // TODO:
    //
    // Remove the need for affinity. This will require the implementation of
    // VMCS migration.
    //
    set_affinity(0);

    ret = create_domain(&vm);
    if (ret != SUCCESS) {
        BFALERT("create_domain failed\n");
        return EXIT_FAILURE;
    }

    ret = read_binary(&vm, argv[1]);
    if (ret != SUCCESS) {
        BFALERT("read_binary failed\n");
        return EXIT_FAILURE;
    }

    ret = load_binary(&vm);
    if (ret != SUCCESS) {
        BFALERT("load_binary failed\n");
        return EXIT_FAILURE;
    }

    ret = create_vcpu(&vm);
    if (ret != SUCCESS) {
        BFALERT("create_vcpu failed\n");
        return EXIT_FAILURE;
    }

    ret = run_vcpu(&vm);
    if (ret != SUCCESS) {
        BFALERT("run_vcpu failed\n");
        return EXIT_FAILURE;
    }

    ret = destroy_vcpu(&vm);
    if (ret != SUCCESS) {
        BFALERT("destroy_vcpu failed\n");
        return EXIT_FAILURE;
    }

    ret = destroy_domain(&vm);
    if (ret != SUCCESS) {
        BFALERT("destroy_domain failed\n");
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
