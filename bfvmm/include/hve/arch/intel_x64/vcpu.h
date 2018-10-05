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
    void write_guest_state(hyperkernel::intel_x64::domain *domain)
    {
        using namespace ::intel_x64;
        using namespace ::intel_x64::vmcs;
        using namespace ::intel_x64::cpuid;

        using namespace ::x64::access_rights;
        using namespace ::x64::segment_register;

        uint64_t cr0 = 0;
        cr0 |= cr0::protection_enable::mask;
        cr0 |= cr0::monitor_coprocessor::mask;
        cr0 |= cr0::extension_type::mask;
        cr0 |= cr0::numeric_error::mask;
        cr0 |= cr0::write_protect::mask;
        cr0 |= cr0::paging::mask;

        uint64_t cr4 = 0;
        cr4 |= cr4::physical_address_extensions::mask;
        cr4 |= cr4::page_global_enable::mask;
        cr4 |= cr4::vmx_enable_bit::mask;
        cr4 |= cr4::osfxsr::mask;
        cr4 |= cr4::osxsave::mask;

        uint64_t ia32_efer_msr = 0;
        ia32_efer_msr |= ::intel_x64::msrs::ia32_efer::lme::mask;
        ia32_efer_msr |= ::intel_x64::msrs::ia32_efer::lma::mask;
        ia32_efer_msr |= ::intel_x64::msrs::ia32_efer::nxe::mask;

        uint64_t cs_index = 1;
        uint64_t ss_index = 2;
        uint64_t fs_index = 3;
        uint64_t gs_index = 4;
        uint64_t tr_index = 5;

        vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);

        guest_cs_selector::set(cs_index << 3);
        guest_ss_selector::set(ss_index << 3);
        guest_fs_selector::set(fs_index << 3);
        guest_gs_selector::set(gs_index << 3);
        guest_tr_selector::set(tr_index << 3);

        guest_ia32_pat::set(domain->pat());
        guest_ia32_efer::set(ia32_efer_msr);

        guest_gdtr_limit::set(domain->gdt()->limit());
        guest_idtr_limit::set(domain->idt()->limit());

        guest_gdtr_base::set(domain->gdt_virt());
        guest_idtr_base::set(domain->idt_virt());

        guest_cs_limit::set(domain->gdt()->limit(cs_index));
        guest_ss_limit::set(domain->gdt()->limit(ss_index));
        guest_fs_limit::set(domain->gdt()->limit(fs_index));
        guest_gs_limit::set(domain->gdt()->limit(gs_index));
        guest_tr_limit::set(domain->gdt()->limit(tr_index));

        guest_cs_access_rights::set(domain->gdt()->access_rights(cs_index));
        guest_ss_access_rights::set(domain->gdt()->access_rights(ss_index));
        guest_fs_access_rights::set(domain->gdt()->access_rights(fs_index));
        guest_gs_access_rights::set(domain->gdt()->access_rights(gs_index));
        guest_tr_access_rights::set(domain->gdt()->access_rights(tr_index));

        guest_es_access_rights::set(guest_es_access_rights::unusable::mask);
        guest_ds_access_rights::set(guest_ds_access_rights::unusable::mask);
        guest_ldtr_access_rights::set(guest_ldtr_access_rights::unusable::mask);

        guest_cs_base::set(domain->gdt()->base(cs_index));
        guest_ss_base::set(domain->gdt()->base(ss_index));
        guest_fs_base::set(domain->gdt()->base(fs_index));
        guest_gs_base::set(domain->gdt()->base(gs_index));
        guest_tr_base::set(domain->gdt()->base(tr_index));

        guest_cr0::set(cr0);
        guest_cr3::set(domain->cr3());
        guest_cr4::set(cr4);

        guest_rflags::set(2);
        cr4_read_shadow::set(cr4);

        this->set_eptp(domain->ept());
    }

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

public:

    domain *m_domain{};
    vcpu *m_parent_vcpu{};

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
