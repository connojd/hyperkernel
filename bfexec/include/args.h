//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

#include "cxxopts.hpp"

using args_type = cxxopts::ParseResult;

inline bool verbose = false;
inline cxxopts::Options options("bfexec", "execute's a virtual machine");

inline args_type
parse_args(int argc, char *argv[])
{
    using namespace cxxopts;

    options.add_options()
        ("h,help", "Print this help menu")
        ("v,verbose", "Enable verbose output")
        ("version", "Print the version")
        ("affinity", "The host CPU to execute the VM on", value<uint64_t>(), "[core #]")
        ("attach", "Attach to a VM that was already created", value<uint64_t>(), "[domid]")
        ("elf", "Create a VM from an ELF file and attach to it")
        ("path", "The VM's path", value<std::string>(), "[path]")
        ("size", "The VM's total RAM", value<uint64_t>(), "[bytes]")
        ("init", "The VM's init process", value<std::string>(), "[path]")
        ("cmdline", "Additional Linux command line arguments", value<std::string>(), "[text]")
        ("uart", "Give the VM an emulated UART", value<uint64_t>(), "[port #]")
        ("pt_uart", "Pass-through a UART to VM", value<uint64_t>(), "[port #]")
        ("ndvm", "The VM is the NDVM")
        ("bus", "The NDVMs PCI bus", value<uint64_t>(), "[bus #]");

    auto args = options.parse(argc, argv);

    if (args.count("help")) {
        std::cout << options.help() << '\n';
        exit(EXIT_SUCCESS);
    }

    if (args.count("version")) {
        std::cout << "version: N/A" << '\n';
        exit(EXIT_SUCCESS);
    }

    if (args.count("ndvm") && !args.count("bus")) {
        throw std::runtime_error("Must specify bus for NDVM");
    }

    if (args.count("verbose")) {
        verbose = true;
    }

    if (args.count("attach") && args.count("elf")) {
        throw std::runtime_error("cannot set both 'attach' and 'elf'");
    }

    if (!args.count("attach") && !args.count("elf")) {
        throw std::runtime_error("must specify 'elf' or 'attach'");
    }

    if (args.count("uart") && args.count("pt_uart")) {
        throw std::runtime_error("must specify 'uart' or 'pt_uart'");
    }

    return args;
}


