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

#include <queue>

#include "vmexit/external_interrupt.h"
#include "vmexit/fault.h"
#include "vmexit/vmcall.h"

#include "vmcall/domain_op.h"
#include "vmcall/vcpu_op.h"
#include "vmcall/bf86_op.h"

#include "xen/xen_op.h"

#include "domain.h"
#include "lapic.h"

#include <bfvmm/vcpu/vcpu_manager.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

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
        gsl::not_null<domain *> domain);

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

    /// Write Dom0 Guest State
    ///
    /// @expects
    /// @ensures
    ///
    void write_dom0_guest_state(domain *domain);

    /// Write DomU Guest State
    ///
    /// @expects
    /// @ensures
    ///
    void write_domU_guest_state(domain *domain);

public:

    //--------------------------------------------------------------------------
    // Domain Info
    //--------------------------------------------------------------------------

    /// Is Dom0
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if this is dom0, false otherwise
    ///
    bool is_dom0() const;

    /// Is DomU
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if this is a domU, false otherwise
    ///
    bool is_domU() const;

    /// Domain ID
    ///
    /// @expects
    /// @ensures
    ///
    /// @return the vCPU's domid
    ///
    domain::domainid_type domid() const;

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

    /// Return and sleep
    ///
    /// Return to the parent vCPU (i.e. resume the parent), and tell the parent
    /// to put the child vCPU asleep for the specified number of microseconds
    ///
    /// @expects
    /// @ensures
    ///
    /// @param us the number of microseconds to sleep
    ///
    VIRTUAL void return_and_sleep(uint64_t us);

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

    /// Sleep
    ///
    /// Tells the vCPU to enter the sleep state
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void sleep();

    /// Wake
    ///
    /// Tells the vCPU to enter the wake state
    ///
    /// @expects
    /// @ensures
    ///
    VIRTUAL void wake(bfobject *obj);

    /// Is Alive
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if the vCPU has not been killed, false otherwise
    ///
    VIRTUAL bool is_alive() const;

    /// Is Killed
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true if the vCPU has been killed, false otherwise
    ///
    VIRTUAL bool is_killed() const;

    /// Is Asleep
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true iff the vCPU is in the sleep state
    ///
    VIRTUAL bool is_asleep() const;

    /// Is Awake
    ///
    /// @expects
    /// @ensures
    ///
    /// @return returns true only iff the vCPU is in the wake state
    ///
    VIRTUAL bool is_awake() const;

    //--------------------------------------------------------------------------
    // LAPIC
    //--------------------------------------------------------------------------

    /// APIC ID
    ///
    /// The APIC ID and the vCPU ID do not need to agree, and on some systems
    /// they don't. This provides that level of flexibility by returning the
    /// APIC's ID
    ///
    /// @return APIC ID
    ///
    VIRTUAL uint32_t lapicid() const;

    /// APIC Base
    ///
    /// This function returns the APIC base for this APIC as a GPA. The HPA is
    /// maintained internally to this class and is not accessible.
    ///
    /// @return APIC base GPA
    ///
    VIRTUAL uint64_t lapic_base() const;

    /// Read
    ///
    /// @param indx the dword offset to read from
    /// @return the 32-bit value of the register
    ///
    VIRTUAL uint32_t lapic_read(uint32_t indx) const;

    /// Write
    ///
    /// @param indx the dword offset to write to
    /// @param val the 32-bit value to write
    ///
    VIRTUAL void lapic_write(uint32_t indx, uint32_t val);

    /// Set timer vector
    ///
    /// @param vector the vector of the timer interrupt
    ///
    VIRTUAL void set_timer_vector(uint64_t vector);

    /// Queue timer interrupt
    ///
    /// Queue the timer interrupt for injection into the guest
    ///
    VIRTUAL void queue_timer_interrupt();

    //--------------------------------------------------------------------------
    // Resources
    //--------------------------------------------------------------------------

    /// E820 Map
    ///
    /// @return the E820 map associated with this vCPU. This is set by the
    /// domain builder using hypercalls.
    ///
    std::vector<e820_entry_t> &e820_map();

    /// Domain
    ///
    /// @return the domain this vcpu belongs to
    ///
    domain *dom();

private:

    domain *m_domain{};
    lapic m_lapic;

    external_interrupt_handler m_external_interrupt_handler;
    fault_handler m_fault_handler;
    vmcall_handler m_vmcall_handler;

    vmcall_domain_op_handler m_vmcall_domain_op_handler;
    vmcall_vcpu_op_handler m_vmcall_vcpu_op_handler;
    vmcall_bf86_op_handler m_vmcall_bf86_op_handler;

    xen_op_handler m_xen_op_handler;

    bool m_killed{};
    bool m_asleep{};

    vcpu *m_parent_vcpu{};
    uint64_t m_timer_vector{};
};

}

//------------------------------------------------------------------------------
// Helpers
//------------------------------------------------------------------------------

// Note:
//
// Undefine previously defined helper macros. Note that these are used by
// each extension to provide quick access to the vcpu in the extension. If
// include files are not handled properly, you could end up with the wrong
// vcpu, resulting in compilation errors
//

#ifdef get_vcpu
#undef get_vcpu
#endif

#ifdef vcpu_cast
#undef vcpu_cast
#endif

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
#define get_vcpu(a) \
    g_vcm->get<hyperkernel::intel_x64::vcpu *>(a, __FILE__ ": invalid hyperkernel vcpuid")

#define vcpu_cast(a) \
    static_cast<hyperkernel::intel_x64::vcpu *>(a.get())

inline bfobject world_switch;

#endif
