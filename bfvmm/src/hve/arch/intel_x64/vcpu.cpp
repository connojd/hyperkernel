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

#include <intrinsics.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/fault.h>

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

//--------------------------------------------------------------------------
// Fault Handlers
//--------------------------------------------------------------------------

static bool
cpuid_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    bferror_info(0, "cpuid_handler executed. unsupported!!!");
    fault(vcpu);

    // Unreachable
    return true;
}

static bool
io_instruction_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    bferror_info(0, "io_instruction_handler executed. unsupported!!!");
    fault(vcpu);

    // Unreachable
    return true;
}

static bool
rdmsr_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    bferror_info(0, "rdmsr_handler executed. unsupported!!!");
    fault(vcpu);

    // Unreachable
    return true;
}

static bool
wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    bferror_info(0, "wrmsr_handler executed. unsupported!!!");
    fault(vcpu);

    // Unreachable
    return true;
}

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

vcpu::vcpu(
    vcpuid::type id,
    gsl::not_null<hyperkernel::intel_x64::domain *> domain
) :
    eapis::intel_x64::vcpu{
        id, domain->global_state()
    },

    m_domain{domain},

    m_external_interrupt_handler{this},
    m_fault_handler{this},
    m_vmcall_handler{this},

    m_vmcall_domain_op_handler{this},
    m_vmcall_vcpu_op_handler{this},
    m_vmcall_bf86_op_handler{this},

    m_xen_op_handler{this}
{
    if (domain->id() == 0) {
        this->write_dom0_guest_state(domain);
    }
    else {
        this->write_domU_guest_state(domain);
    }
}

//--------------------------------------------------------------------------
// Setup
//--------------------------------------------------------------------------

void
vcpu::write_dom0_guest_state(domain *domain)
{
    this->set_eptp(domain->ept());
}

void
vcpu::write_domU_guest_state(domain *domain)
{
    using namespace ::intel_x64;
    using namespace ::intel_x64::vmcs;
    using namespace ::intel_x64::cpuid;

    using namespace ::x64::access_rights;
    using namespace ::x64::segment_register;

    uint64_t cr0 = guest_cr0::get();
    cr0 |= cr0::protection_enable::mask;
    cr0 |= cr0::monitor_coprocessor::mask;
    cr0 |= cr0::extension_type::mask;
    cr0 |= cr0::numeric_error::mask;
    cr0 |= cr0::write_protect::mask;

    uint64_t cr4 = guest_cr4::get();
    cr4 |= cr4::vmx_enable_bit::mask;

    guest_cr0::set(cr0);
    guest_cr4::set(cr4);

    vm_entry_controls::ia_32e_mode_guest::disable();

    uint64_t es_index = 3;
    uint64_t cs_index = 2;
    uint64_t ss_index = 3;
    uint64_t ds_index = 3;
    uint64_t fs_index = 3;
    uint64_t gs_index = 3;
    uint64_t tr_index = 4;

    guest_es_selector::set(es_index << 3);
    guest_cs_selector::set(cs_index << 3);
    guest_ss_selector::set(ss_index << 3);
    guest_ds_selector::set(ds_index << 3);
    guest_fs_selector::set(fs_index << 3);
    guest_gs_selector::set(gs_index << 3);
    guest_tr_selector::set(tr_index << 3);

    guest_es_limit::set(domain->gdt()->limit(es_index));
    guest_cs_limit::set(domain->gdt()->limit(cs_index));
    guest_ss_limit::set(domain->gdt()->limit(ss_index));
    guest_ds_limit::set(domain->gdt()->limit(ds_index));
    guest_fs_limit::set(domain->gdt()->limit(fs_index));
    guest_gs_limit::set(domain->gdt()->limit(gs_index));
    guest_tr_limit::set(domain->gdt()->limit(tr_index));

    guest_es_access_rights::set(domain->gdt()->access_rights(es_index));
    guest_cs_access_rights::set(domain->gdt()->access_rights(cs_index));
    guest_ss_access_rights::set(domain->gdt()->access_rights(ss_index));
    guest_ds_access_rights::set(domain->gdt()->access_rights(ds_index));
    guest_fs_access_rights::set(domain->gdt()->access_rights(fs_index));
    guest_gs_access_rights::set(domain->gdt()->access_rights(gs_index));
    guest_tr_access_rights::set(domain->gdt()->access_rights(tr_index));

    guest_ldtr_access_rights::set(guest_ldtr_access_rights::unusable::mask);

    guest_es_base::set(domain->gdt()->base(es_index));
    guest_cs_base::set(domain->gdt()->base(cs_index));
    guest_ss_base::set(domain->gdt()->base(ss_index));
    guest_ds_base::set(domain->gdt()->base(ds_index));
    guest_fs_base::set(domain->gdt()->base(fs_index));
    guest_gs_base::set(domain->gdt()->base(gs_index));
    guest_tr_base::set(domain->gdt()->base(tr_index));

    guest_rflags::set(2);
    vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);

    this->set_eptp(domain->ept());

    this->trap_on_all_io_instruction_accesses();
    this->trap_on_all_rdmsr_accesses();
    this->trap_on_all_wrmsr_accesses();

    this->pass_through_rdmsr_access(0xc0000080);
    this->pass_through_wrmsr_access(0xc0000080);
    this->pass_through_rdmsr_access(0xc0000100);
    this->pass_through_wrmsr_access(0xc0000100);
    this->pass_through_rdmsr_access(0xc0000101);
    this->pass_through_wrmsr_access(0xc0000101);
    this->pass_through_rdmsr_access(0xc0000102);
    this->pass_through_wrmsr_access(0xc0000102);

    this->add_default_cpuid_handler(
        ::handler_delegate_t::create<cpuid_handler>()
    );

    this->add_default_wrmsr_handler(
        ::handler_delegate_t::create<wrmsr_handler>()
    );

    this->add_default_rdmsr_handler(
        ::handler_delegate_t::create<rdmsr_handler>()
    );

    this->add_handler(
        exit_reason::basic_exit_reason::io_instruction,
        ::handler_delegate_t::create<io_instruction_handler>()
    );
}

//--------------------------------------------------------------------------
// VMCall
//--------------------------------------------------------------------------

gsl::not_null<vmcall_handler *>
vcpu::vmcall()
{ return &m_vmcall_handler; }

void
vcpu::add_vmcall_handler(
    const vmcall_handler::handler_delegate_t &d)
{ m_vmcall_handler.add_handler(std::move(d)); }

//--------------------------------------------------------------------------
// Parent vCPU
//--------------------------------------------------------------------------

void
vcpu::set_parent_vcpu(gsl::not_null<vcpu *> vcpu)
{ m_parent_vcpu = vcpu; }

vcpu *
vcpu::parent_vcpu() const
{ return m_parent_vcpu; }

void
vcpu::return_success()
{
    this->set_rax(SUCCESS);
    vmcs_n::guest_rflags::carry_flag::disable();

    this->run();
}

void
vcpu::return_failure()
{
    this->set_rax(FAILURE);
    vmcs_n::guest_rflags::carry_flag::disable();

    this->run();
}

void
vcpu::return_and_continue()
{
    vmcs_n::guest_rflags::carry_flag::enable();

    this->run();
}

//--------------------------------------------------------------------------
// Control
//--------------------------------------------------------------------------

void
vcpu::kill()
{ m_killed = true; }

bool
vcpu::is_killed() const
{ return m_killed; }

}
