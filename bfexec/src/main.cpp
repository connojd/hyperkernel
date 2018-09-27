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

#include <gsl/gsl>

#include <vector>
#include <iostream>

#include <hypercall.h>

#include <bffile.h>
#include <bfelf_loader.h>

// TODO:
//
// The arg passed to bfexec should be a json file, and not the filename
// itself. This way, we can store settings like the total number of vCPUs,
// memory, etc...
//

using arg_type = std::string;
using arg_list_type = std::vector<arg_type>;

#define MAX_NUM_VCPUIDS 1

struct vm_t
{
    struct crt_info_t crt_info;
    struct bfelf_loader_t bfelf_loader;
    struct bfelf_binary_t bfelf_binary;

    void *entry;
    file::binary_data binary;

    uint64_t domainid;
    uint64_t vcpuids[MAX_NUM_VCPUIDS];
};

void
read_binary(struct vm_t &vm, const std::string &filename)
{
    file f;
    vm.binary = f.read_binary(filename);

    vm.bfelf_binary.file = vm.binary.get();
    vm.bfelf_binary.file_size = vm.binary.size();
}

void
load_binary(struct vm_t &vm)
{
    auto ret =
        bfelf_load(
            &vm.bfelf_binary,
            1,
            &vm.entry,
            &vm.crt_info,
            &vm.bfelf_loader
        );

    if (ret != BF_SUCCESS) {
        throw std::runtime_error("failed to load ELF file");
    }
}

int
protected_main(const arg_list_type &args)
{
    struct vm_t vm{};

    if (args.empty()) {
        throw std::runtime_error("missing name of ELF file to load");
    }

    if (ack() == 0) {
        throw std::runtime_error("hypervisor not running");
    }

    read_binary(vm, args.at(0));
    load_binary(vm);

    auto create_domain_arg = create_domain_arg_t{};
    vm.domainid = create_domain(&create_domain_arg);

    uint64_t vcpuid_index = 0;

    auto create_vcpu_arg = create_vcpu_arg_t{
        vm.domainid
    };

    vm.vcpuids[vcpuid_index++] = create_vcpu(&create_vcpu_arg);

    return EXIT_SUCCESS;
}

int
main(int argc, const char *argv[])
{
    try {
        arg_list_type args;
        auto args_span = gsl::make_span(argv, argc);

        for (auto i = 1; i < argc; i++) {
            args.emplace_back(args_span[i]);
        }

        return protected_main(args);
    }
    catch (std::exception &e) {
        std::cerr << "Caught unhandled exception:" << '\n';
        std::cerr << "    - what(): " << e.what() << '\n';
    }
    catch (...) {
        std::cerr << "Caught unknown exception" << '\n';
    }

    return EXIT_FAILURE;
}
