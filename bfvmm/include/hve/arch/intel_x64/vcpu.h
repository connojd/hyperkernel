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

#include "xen/xen_op.h"

#include "domain.h"

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

    //--------------------------------------------------------------------------
    // Memory Mapping
    //--------------------------------------------------------------------------

    /// Get Entry
    ///
    /// Given a GPA to a pml4, pdpt, pd or pt and an index, this function will
    /// return the table entry.
    ///
    /// @param tble_gpa the guest physical address of the table to
    ///     get the entry from.
    /// @param index the index into the table
    /// @return tble_gpa[index]
    ///
    uintptr_t get_entry(uintptr_t tble_gpa, std::ptrdiff_t index);

    /// Get Entry Delegate Instance
    ///
    /// The following is an instantiation of the get_entry delegate that can
    /// be used for getting a PTE if the GPA == the HPA
    ///
    bfvmm::x64::get_entry_delegate_t get_entry_delegate =
        bfvmm::x64::get_entry_delegate_t::create<vcpu, &vcpu::get_entry>(this);

    /// Convert GPA to HPA
    ///
    /// Converts a guest physical address to a host physical address
    /// using EPT.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gpa_to_hpa(uint64_t gpa);

    /// Convert GVA to GPA
    ///
    /// Converts a guest virtual address to a guest physical address
    /// using EPT.
    ///
    /// Note:
    /// - This function assumes that this vCPU is loaded when you run this
    ///   function. If this vCPU is not loaded, you will end up parsing the
    ///   GVA associated with whatever vCPU is currently loaded leading to
    ///   possible corruption. The reason for this is this function uses
    ///   the VMCS's guest_cr3.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting guest physical address
    ///
    std::pair<uintptr_t, uintptr_t> gva_to_gpa(uint64_t gva);

    /// Convert GVA to HPA
    ///
    /// Converts a guest virtual address to a host physical address
    /// using EPT.
    ///
    /// Note:
    /// - This function assumes that this vCPU is loaded when you run this
    ///   function. If this vCPU is not loaded, you will end up parsing the
    ///   GVA associated with whatever vCPU is currently loaded leading to
    ///   possible corruption. The reason for this is this function uses
    ///   the VMCS's guest_cr3.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gva the guest virtual address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gva_to_hpa(uint64_t gva);

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(uintptr_t gpa)
    { return m_domain->map_gpa_1g<T>(gpa); }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(uintptr_t gpa)
    { return m_domain->map_gpa_2m<T>(gpa); }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(uintptr_t gpa)
    { return m_domain->map_gpa_4k<T>(gpa); }

    /// Map GVA (4k)
    ///
    /// Map a 4k guest virtual address. This function will automatically convert
    /// the provided GVA to a HPA and then map.
    /// The result of this function is a unique_map that will unmap when scope
    /// is lost, and the map's pointer will be properly positioned to align with
    /// lower bits of the provided GVA (meaning, the GVA does not need to be
    /// page aligned, and any offset in the GVA will be reflected in the provided
    /// map)
    ///
    /// @expects
    ///
    /// @param gva the guest virtual address
    /// @param len the number of bytes to map
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gva_4k(uintptr_t gva, std::size_t len)
    {
        return
            bfvmm::x64::map_gva_4k<T>(
                gva,
                vmcs_n::guest_cr3::get(),
                len,
                get_entry_delegate
            );
    }

    /// Map GVA (4k)
    ///
    /// Map a 4k guest virtual address. This function will automatically convert
    /// the provided GVA to a HPA and then map.
    /// The result of this function is a unique_map that will unmap when scope
    /// is lost, and the map's pointer will be properly positioned to align with
    /// lower bits of the provided GVA (meaning, the GVA does not need to be
    /// page aligned, and any offset in the GVA will be reflected in the provided
    /// map)
    ///
    /// @expects
    ///
    /// @param gva the guest virtual address
    /// @param len the number of bytes to map
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gva_4k(void *gva, std::size_t len)
    { return map_gva_4k<T>(reinterpret_cast<uintptr_t>(gva), len); }

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

    xen_op_handler m_xen_op_handler;
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

#endif
