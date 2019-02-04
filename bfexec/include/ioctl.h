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

#ifndef IOCTL_H
#define IOCTL_H

#include <memory>

#include <bfgsl.h>
#include <bfbuilderinterface.h>

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4251)
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

/// IOCTL Private Base
///
/// Only needed for dynamic cast
///
class ioctl_private_base
{
public:

    /// Default Constructor
    ///
    ioctl_private_base() = default;

    /// Default Destructor
    ///
    virtual ~ioctl_private_base() = default;
};

/// IOCTL
///
/// Calls into the bareflank driver entry to perform a desired action. Note
/// that for this class to function, the driver entry must be loaded, and
/// bfm must be executed with the proper permissions.
///
class ioctl
{
public:

    using file_type = std::vector<gsl::byte>;
    using size_type = std::size_t;

    /// Default Constructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ioctl();

    /// Destructor
    ///
    /// @expects none
    /// @ensures none
    ///
    ~ioctl() = default;

    /// Create VM from ELF
    ///
    /// Creates a virtual machine given an ELF file.
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param args the args needed to create the VM
    ///
    void call_ioctl_create_from_elf(create_from_elf_args &args);

    /// Destroy VM
    ///
    /// Destroys a VM given a domain ID
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param domainid the domain to destroy
    ///
    void call_ioctl_destroy(domainid_t domainid) noexcept;

private:

    std::unique_ptr<ioctl_private_base> m_d;
};

#ifdef _MSC_VER
#pragma warning(pop)
#endif

#endif
