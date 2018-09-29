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

#ifndef VCPU_GUEST_INTEL_X64_HYPERKERNEL_H
#define VCPU_GUEST_INTEL_X64_HYPERKERNEL_H

#include "apis.h"
#include <eapis/hve/arch/intel_x64/vcpu.h>

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;



namespace hyperkernel::intel_x64
{

/// vCPU
///
class vcpu_guest_state_t : public bfobject
{
    domain *m_domain;

public:

    vcpu_guest_state_t(
        gsl::not_null<domain *> domain
    ) :
        m_domain{domain}
    { }

    gsl::not_null<domain *> domain()
    { return m_domain; }
};

/// vCPU
///
class vcpu_guest : public eapis::intel_x64::vcpu
{
    domain *m_domain;

public:

    bool
    ept_handler(
        gsl::not_null<vmcs_t *> vmcs)
    {
        using namespace ::intel_x64::vmcs;

        guard_exceptions([&] {
            bferror_subnhex(0, "rip", vmcs->save_state()->rip);
            bferror_subnhex(0, "rsp", vmcs->save_state()->rsp);

            bferror_subnhex(0, "linear address", guest_linear_address::get());
            bferror_subnhex(0, "physical address", guest_physical_address::get());

            bfdebug_bool(0, "is_4k", m_domain->ept().is_4k(0x0000000000301000));
            bfdebug_nhex(0, "vrt_to_phys", m_domain->ept().virt_to_phys(0x0000000000301000));

            auto entry = m_domain->ept().entry(0x0000000000301000);
            bfdebug_nhex(0, "entry", entry);
        });

        g_vmcs->load();
        advance(g_vmcs);
        g_vmcs->save_state()->rax = FAILURE;
        vmcs_resume(g_vmcs->save_state());

        return true;
    }

    bool
    resume_handler(
        gsl::not_null<vmcs_t *> vmcs)
    {
        using namespace ::intel_x64::vmcs;

        bferror_lnbr(0);
        bferror_info(0, "killing guest");
        bferror_brk1(0);

        bferror_subnhex(0, "rax", vmcs->save_state()->rax);
        bferror_subnhex(0, "rbx", vmcs->save_state()->rbx);
        bferror_subnhex(0, "rcx", vmcs->save_state()->rcx);
        bferror_subnhex(0, "rdx", vmcs->save_state()->rdx);
        bferror_subnhex(0, "rbp", vmcs->save_state()->rbp);
        bferror_subnhex(0, "rsi", vmcs->save_state()->rsi);
        bferror_subnhex(0, "rdi", vmcs->save_state()->rdi);
        bferror_subnhex(0, "r08", vmcs->save_state()->r08);
        bferror_subnhex(0, "r09", vmcs->save_state()->r09);
        bferror_subnhex(0, "r10", vmcs->save_state()->r10);
        bferror_subnhex(0, "r11", vmcs->save_state()->r11);
        bferror_subnhex(0, "r12", vmcs->save_state()->r12);
        bferror_subnhex(0, "r13", vmcs->save_state()->r13);
        bferror_subnhex(0, "r14", vmcs->save_state()->r14);
        bferror_subnhex(0, "r15", vmcs->save_state()->r15);
        bferror_subnhex(0, "rip", vmcs->save_state()->rip);
        bferror_subnhex(0, "rsp", vmcs->save_state()->rsp);

        bferror_subnhex(0, "cr0", guest_cr0::get());
        bferror_subnhex(0, "cr2", ::intel_x64::cr2::get());
        bferror_subnhex(0, "cr3", guest_cr3::get());
        bferror_subnhex(0, "cr4", guest_cr4::get());

        bferror_subnhex(0, "linear address", guest_linear_address::get());
        bferror_subnhex(0, "physical address", guest_physical_address::get());

        bferror_subnhex(0, "exit reason", exit_reason::get());
        bferror_subnhex(0, "exit qualification", exit_qualification::get());

        g_vmcs->load();
        advance(g_vmcs);
        g_vmcs->save_state()->rax = FAILURE;
        vmcs_resume(g_vmcs->save_state());

        return true;
    }

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    ///
    /// @cond
    ///
    explicit vcpu_guest(
        vcpuid::type id,
        gsl::not_null<vcpu_guest_state_t *> vcpu_guest_state
    ) :
        eapis::intel_x64::vcpu{
            id,
            vcpu_guest_state->domain()->eapis_vcpu_global_state()
        },
        m_apis{
            vmcs(),
            exit_handler(),
            vcpu_guest_state->domain().get()
        },
        m_domain(vcpu_guest_state->domain())
    {
        using namespace ::intel_x64;
        using namespace ::intel_x64::vmcs;
        using namespace ::intel_x64::cpuid;

        using namespace ::x64::access_rights;
        using namespace ::x64::segment_register;

        auto domain = vcpu_guest_state->domain();

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

        eapis()->set_eptp(domain->ept());


        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::ept_violation,
            ::handler_delegate_t::create<vcpu_guest, &vcpu_guest::ept_handler>(this)
        );

        exit_handler()->add_handler(
            exit_reason::basic_exit_reason::triple_fault,
            ::handler_delegate_t::create<vcpu_guest, &vcpu_guest::resume_handler>(this)
        );
    }

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu_guest() = default;

    /// APIs
    ///
    /// @expects
    /// @ensures
    ///
    /// @return a pointer to the hkapis
    ///
    gsl::not_null<apis *> hkapis()
    { return &m_apis; }

    void load()
    { vmcs()->load(); }

    void launch()
    { vmcs()->launch(); }

    void resume()
    { vmcs()->resume(); }














private:

    apis m_apis;
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
#define get_guest_vcpu(a) \
    g_vcm->get<hyperkernel::intel_x64::vcpu_guest *>(a, "invalid vcpuid: " __FILE__)

#endif
