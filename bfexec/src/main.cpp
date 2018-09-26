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

#include "../../include/hypercall.h"

using arg_type = std::string;
using arg_list_type = std::vector<arg_type>;

int
protected_main(const arg_list_type &args)
{
    auto create_domain_arg = create_domain_arg_t{};
    std::cout << create_domain(&create_domain_arg) << '\n';

//     for (auto i = 0; i < 1; i++)
//         g_vcpus.push_back(std::make_unique<vcpu>(g_proclt->id()));

//     for (const auto &arg : args)
//         g_processes.push_back(std::make_unique<process>(arg, g_proclt->id()));

//     if (!vmcall__sched_yield())
//         throw std::runtime_error("vmcall__sched_yield failed");

    return EXIT_SUCCESS;
}

void
bfexec_terminate()
{
    std::cerr << "FATAL ERROR: terminate called" << '\n';
    abort();
}

void
bfexec_new_handler()
{
    std::cerr << "FATAL ERROR: out of memory" << '\n';
    abort();
}

int
main(int argc, const char *argv[])
{
    std::set_terminate(bfexec_terminate);
    std::set_new_handler(bfexec_new_handler);

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
