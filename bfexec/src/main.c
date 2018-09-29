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
};

/* -------------------------------------------------------------------------- */
/* ELF File Functions                                                         */
/* -------------------------------------------------------------------------- */

void
read_binary(struct vm_t *vm, const char *filename)
{
    char *data;
    uint64_t size;

    vm->file = fopen(filename, "rb");
    if (vm->file == 0) {
        fprintf(stderr, "failed to open: %s\n", filename);
        exit(EXIT_FAILURE);
    }

    if (fseek(vm->file, 0, SEEK_END) != 0) {
        fprintf(stderr, "fseek failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    size = (uint64_t)ftell(vm->file);
    if (size == (uint64_t)-1) {
        fprintf(stderr, "ftell failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (fseek(vm->file, 0, SEEK_SET) != 0) {
        fprintf(stderr, "fseek failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    data = (char *)aligned_alloc(0x1000, size);
    if (data == 0) {
        fprintf(stderr, "malloc failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (fread(data, 1, size, vm->file) != size) {
        fprintf(stderr, "fread failed to read entire file: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    vm->bfelf_binary.file = data;
    vm->bfelf_binary.file_size = size;
    vm->bfelf_binary.exec_virt = (char *)0x100000;
}

void
load_binary(struct vm_t *vm)
{
    status_t ret =
        bfelf_load(
            &vm->bfelf_binary,
            1,
            &vm->entry,
            &vm->crt_info,
            &vm->bfelf_loader
        );

    if (ret != BF_SUCCESS) {
        fprintf(stderr, "bfelf_load: 0x%016" PRIx64 "\n", ret);
        exit(EXIT_FAILURE);
    }

    vm->stack = aligned_alloc(0x1000, STACK_SIZE);
    if (vm->stack == 0) {
        fprintf(stderr, "malloc failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

/* -------------------------------------------------------------------------- */
/* Domain Functions                                                           */
/* -------------------------------------------------------------------------- */

void
create_domain(struct vm_t *vm)
{
    struct domain_op__create_domain_arg_t domain_op__create_domain_arg;

    vm->domainid = domain_op__create_domain(&domain_op__create_domain_arg);
    if (vm->domainid == INVALID_DOMAINID) {
        fprintf(stderr, "create_domain failed\n");
        exit(EXIT_FAILURE);
    }
}

void
map_4k(struct vm_t *vm, const char *page, uintptr_t exec)
{
    struct domain_op__map_4k_arg_t domain_op__map_4k_arg = {
        vm->domainid,
        (uintptr_t) page,
        exec
    };

    status_t ret = domain_op__map_4k(&domain_op__map_4k_arg);
    if (ret != SUCCESS) {
        fprintf(stderr, "map_4k failed\n");
        exit(EXIT_FAILURE);
    }
}

void
map_binary(struct vm_t *vm)
{
    uintptr_t index;

    if (mlock(vm->bfelf_binary.exec, vm->bfelf_binary.exec_size) != 0) {
        fprintf(stderr, "mlock failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    if (mlock(vm->stack, STACK_SIZE) != 0) {
        fprintf(stderr, "mlock failed: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    for (index = 0; index < STACK_SIZE; index += 0x1000) {
        map_4k(vm, (char *)vm->stack + index, 0x10000 + index);
    }

    for (index = 0; index < vm->bfelf_binary.exec_size; index += 0x1000) {
        // printf("map_4k: %lx   %lx\n", (uintptr_t)(vm->bfelf_binary.exec + index), 0x100000 + index);
        map_4k(vm, vm->bfelf_binary.exec + index, 0x100000 + index);
    }
}

/* -------------------------------------------------------------------------- */
/* vCPU Functions                                                             */
/* -------------------------------------------------------------------------- */

void
create_vcpu(struct vm_t *vm)
{
    struct vcpu_op__create_vcpu_arg_t vcpu_op__create_vcpu_arg = {
        vm->domainid
    };

    vm->vcpuid = vcpu_op__create_vcpu(&vcpu_op__create_vcpu_arg);
    if (vm->vcpuid == INVALID_VCPUID) {
        fprintf(stderr, "create_vcpu failed\n");
        exit(EXIT_FAILURE);
    }
}

void
run_vcpu(struct vm_t *vm)
{
    struct vcpu_op__run_vcpu_arg_t vcpu_op__run_vcpu_arg = {
        vm->vcpuid,
        (uintptr_t)vm->entry,
        // (uintptr_t)vm->stack
        0x10000 + STACK_SIZE - 1
    };

    status_t ret = vcpu_op__run_vcpu(&vcpu_op__run_vcpu_arg);
    if (ret == FAILURE) {
        fprintf(stderr, "run_vcpu failed\n");
        exit(EXIT_FAILURE);
    }
}

/* -------------------------------------------------------------------------- */
/* Main                                                                       */
/* -------------------------------------------------------------------------- */

int
main(int argc, const char *argv[])
{
    bfignored(argc);

    struct vm_t vm;
    memset(&vm, 0, sizeof(vm));

    if (ack() == 0) {
        return EXIT_FAILURE;
    }

    read_binary(&vm, argv[1]);
    load_binary(&vm);

        fprintf(stderr, "entry: %p\n", vm.entry);

    create_domain(&vm);
    map_binary(&vm);
    create_vcpu(&vm);

    run_vcpu(&vm);

    return EXIT_SUCCESS;
}
