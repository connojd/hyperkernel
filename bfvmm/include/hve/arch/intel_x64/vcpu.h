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

#ifndef VCPU_INTEL_X64_HYPERKERNEL_H
#define VCPU_INTEL_X64_HYPERKERNEL_H

#include "vmexit/external_interrupt.h"
#include "vmexit/fault.h"
#include "vmexit/vmcall.h"

#include "vmcall/domain_op.h"
#include "vmcall/vcpu_op.h"
#include "vmcall/bf86_op.h"

#include "domain.h"

#include <bfvmm/vcpu/vcpu_manager.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

namespace hyperkernel::intel_x64
{

class vcpu : public eapis::intel_x64::vcpu
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    ///
    /// @cond
    ///
    explicit vcpu(
        vcpuid::type id,
        hyperkernel::intel_x64::domain *domain = nullptr);

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

    /// Write Guest State
    ///
    /// If this is a guest vCPU, set up the vCPU state as such
    ///
    ///
    void write_guest_state(
        hyperkernel::intel_x64::domain *domain);

public:

    //==========================================================================
    // VMExit
    //==========================================================================

    //--------------------------------------------------------------------------
    // VMCall
    //--------------------------------------------------------------------------

    /// Get VMCall Object
    ///
    /// @expects
    /// @ensures
    ///
    /// @return Returns the VMCall handler stored in the apis if VMCall
    ///     trapping is enabled, otherwise an exception is thrown
    ///
    gsl::not_null<vmcall_handler *> vmcall();

    /// Add VMCall Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the delegate to call when a vmcall exit occurs
    ///
    VIRTUAL void add_vmcall_handler(
        const vmcall_handler::handler_delegate_t &d);

    //--------------------------------------------------------------------------
    // Parent
    //--------------------------------------------------------------------------

    /// Set Parent vCPU
    ///
    /// Each vCPU that is executing (not created) must have a parent. The
    /// only exception to this is the host vCPUs. If a vCPU can no longer
    /// execute (e.g., from a crash, interrupt, hlt, etc...), the parent
    /// vCPU is the parent that will be resumed.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of the vCPU to resume
    ///
    VIRTUAL void set_parent_vcpu(gsl::not_null<vcpu *> vcpu);

    /// Get Parent vCPU ID
    ///
    /// Returns the vCPU ID for this vCPU's parent. Note that this ID could
    /// change on every exit. Specifically when the Host OS moves the
    /// userspace application associated with a guest vCPU. For this reason,
    /// don't cache this value. It always needs to be looked up.
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns the vcpuid for this vCPU's parent vCPU.
    ///
    VIRTUAL vcpu *parent_vcpu() const;

    /// Return Success
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to stop the guest vCPU and report success
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void return_success();

    /// Return Failure
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to stop the guest and report failure
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void return_failure();

    /// Return and Continue
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to resume the guest as fast as possible. This is used to hand control
    /// back to the parent, even though the guest is not finished yet.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void return_and_continue();

    //--------------------------------------------------------------------------
    // Control
    //--------------------------------------------------------------------------

    /// Kill
    ///
    /// Tells the vCPU to stop execution.
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void kill();

    /// Is Killed
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if the vCPU has been killed, false otherwise
    ///
    VIRTUAL bool is_killed() const;


public:

    domain *m_domain{};
    vcpu *m_parent_vcpu{};

    bool m_killed{false};

    external_interrupt_handler m_external_interrupt_handler;
    fault_handler m_fault_handler;
    vmcall_handler m_vmcall_handler;

    vmcall_domain_op_handler m_vmcall_domain_op_handler;
    vmcall_vcpu_op_handler m_vmcall_vcpu_op_handler;
    vmcall_bf86_op_handler m_vmcall_bf86_op_handler;
};

}

/// Get Guest vCPU
///
/// Gets a guest vCPU from the vCPU manager given a vcpuid
///
/// @expects
/// @ensures
///
/// @return returns a pointer to the vCPU being queried or throws
///     and exception.
///
#define get_hk_vcpu(a) \
    g_vcm->get<hyperkernel::intel_x64::vcpu *>(a, __FILE__ ": invalid hk vcpuid")

#endif
