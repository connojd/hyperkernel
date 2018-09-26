//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef VMCALL_DOMAIN_INTEL_X64_HYPERKERNEL_H
#define VMCALL_DOMAIN_INTEL_X64_HYPERKERNEL_H

#include <hve/arch/intel_x64/vmexit/vmcall.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HYPERKERNEL_HVE
#ifdef SHARED_HYPERKERNEL_HVE
#define EXPORT_HYPERKERNEL_HVE EXPORT_SYM
#else
#define EXPORT_HYPERKERNEL_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HYPERKERNEL_HVE
#endif

// -----------------------------------------------------------------------------
// Aliases
// -----------------------------------------------------------------------------

#include <bfvmm/hve/arch/intel_x64/vmcs.h>
#include <bfvmm/hve/arch/intel_x64/exit_handler.h>

using vmcs_t = bfvmm::intel_x64::vmcs;
using exit_handler_t = bfvmm::intel_x64::exit_handler;

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace hyperkernel
{
namespace intel_x64
{

class apis;
class hyperkernel_vcpu_state_t;

/// Interrupt window
///
/// Provides an interface for registering handlers of the interrupt-window exit.
///
class EXPORT_HYPERKERNEL_HVE vmcall_domain_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this interrupt window handler
    /// @param hyperkernel_vcpu_state a pointer to the vCPUs global state
    ///
    vmcall_domain_handler(
        gsl::not_null<apis *> apis,
        gsl::not_null<hyperkernel_vcpu_state_t *> hyperkernel_vcpu_state);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_domain_handler() = default;

public:

    /// @cond

    vmcall_domain_handler(vmcall_domain_handler &&) = default;
    vmcall_domain_handler &operator=(vmcall_domain_handler &&) = default;

    vmcall_domain_handler(const vmcall_domain_handler &) = delete;
    vmcall_domain_handler &operator=(const vmcall_domain_handler &) = delete;

    /// @endcond
};

}
}

#endif
