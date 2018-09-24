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

#ifndef APIS_INTEL_X64_HYPERKERNEL_H
#define APIS_INTEL_X64_HYPERKERNEL_H

#include "vmexit/vmcall.h"
#include <eapis/hve/arch/intel_x64/apis.h>

namespace hyperkernel
{
namespace intel_x64
{

/// Hyperkernel Object
///
/// This is a generic bfobject specific to the hyperkernel that is used for
/// constructing a vCPU.
///
class hyperkernel_vcpu_state_t : public eapis::intel_x64::eapis_vcpu_state_t
{
public:

    /// Constructor
    ///
    /// @param eapis_vcpu_global_state a pointer to a global state struct
    ///
    hyperkernel_vcpu_state_t(
        gsl::not_null<eapis::intel_x64::eapis_vcpu_global_state_t *> eapis_vcpu_global_state
    ) :
        eapis::intel_x64::eapis_vcpu_state_t(eapis_vcpu_global_state)
    { }
};

/// Default vCPU State
///
inline hyperkernel_vcpu_state_t
    g_hyperkernel_vcpu_state_t{&eapis::intel_x64::g_eapis_vcpu_global_state};

/// APIs
///
/// Implements the APIs associated with the Extended APIs, specifically
/// implementing Intel's VT-x and VT-d without the need for guest support.
///
/// This class encapsulates the Extended APIs into a single object that can be
/// referenced by the other APIs as needed. The Intel APIs are circular by
/// design, and as such, some APIs need to be able to use others to complete
/// their job. The class provides a simple way to solve this issue. It should
/// be noted that we don't place these APIs directly into the vCPU to prevent
/// these APIs from being coupled to the vCPU logic that is provided by the
/// based hypervisor and other extensions.
///
class apis
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vmcs the vmcs object associated with the vCPU associated with
    ///     this set of APIs.
    /// @param exit_handler the exit_handler object associated with the vCPU
    ///     associated with this set of APIs.
    ///
    apis(
        gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
        gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL ~apis() = default;

public:

    //==========================================================================
    // Resources
    //==========================================================================

    /// Add Handler Delegate
    ///
    /// Adds a handler to the handler function. When a VM exit occurs, the
    /// handler will call the delegate registered by this function as
    /// as needed. Note that the handlers are called in the reverse order they
    /// are registered (i.e. FIFO).
    ///
    /// @note If the delegate has serviced the VM exit, it should return true,
    ///     otherwise it should return false, and the next delegate registered
    ///     for this VM exit will execute, or an unimplemented exit reason
    ///     error will trigger
    ///
    /// @expects none
    /// @ensures none
    ///
    /// @param reason The exit reason for the handler being registered
    /// @param d The delegate being registered
    ///
    VIRTUAL void add_handler(
        ::intel_x64::vmcs::value_type reason,
        const handler_delegate_t &d);

private:

    bfvmm::intel_x64::vmcs *m_vmcs;
    bfvmm::intel_x64::exit_handler *m_exit_handler;
};

}
}

#endif
