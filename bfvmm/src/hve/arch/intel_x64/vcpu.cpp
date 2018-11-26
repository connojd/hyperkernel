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

#include <hve/arch/intel_x64/lapic.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/fault.h>

//------------------------------------------------------------------------------
// Fault Handlers
//------------------------------------------------------------------------------

static bool
cpuid_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    fault(vcpu, "cpuid_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
rdmsr_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    fault(vcpu, "rdmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    fault(vcpu, "wrmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
io_instruction_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    fault(vcpu, "io_instruction_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

//------------------------------------------------------------------------------
// Implementation
//------------------------------------------------------------------------------

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
    m_lapic{this},

    m_external_interrupt_handler{this},
    m_fault_handler{this},
    m_vmcall_handler{this},

    m_vmcall_domain_op_handler{this},
    m_vmcall_vcpu_op_handler{this},
    m_vmcall_bf86_op_handler{this},

    m_xen_op_handler{this}
{
    if (this->is_dom0()) {
        this->write_dom0_guest_state(domain);
    }
    else {
        this->write_domU_guest_state(domain);
    }
}

//------------------------------------------------------------------------------
// Setup
//------------------------------------------------------------------------------

void
vcpu::write_dom0_guest_state(domain *domain)
{
    this->set_eptp(domain->ept());
}

void
vcpu::write_domU_guest_state(domain *domain)
{
    this->set_eptp(domain->ept());

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

    m_lapic.init();

    using namespace primary_processor_based_vm_execution_controls;
    hlt_exiting::enable();
    rdpmc_exiting::enable();

    using namespace secondary_processor_based_vm_execution_controls;
    enable_invpcid::disable();
    enable_xsaves_xrstors::disable();

    this->add_default_cpuid_handler(
        ::handler_delegate_t::create<cpuid_handler>()
    );

    this->add_default_wrmsr_handler(
        ::handler_delegate_t::create<wrmsr_handler>()
    );

    this->add_default_rdmsr_handler(
        ::handler_delegate_t::create<rdmsr_handler>()
    );

    this->add_default_io_instruction_handler(
        ::handler_delegate_t::create<io_instruction_handler>()
    );
}

//------------------------------------------------------------------------------
// Domain Info
//------------------------------------------------------------------------------

bool
vcpu::is_dom0() const
{ return m_domain->id() == 0; }

bool
vcpu::is_domU() const
{ return m_domain->id() != 0; }

domain::domainid_type
vcpu::domid() const
{ return m_domain->id(); }

//------------------------------------------------------------------------------
// VMCall
//------------------------------------------------------------------------------

gsl::not_null<vmcall_handler *>
vcpu::vmcall()
{ return &m_vmcall_handler; }

void
vcpu::add_vmcall_handler(
    const vmcall_handler::handler_delegate_t &d)
{ m_vmcall_handler.add_handler(std::move(d)); }

//------------------------------------------------------------------------------
// Parent vCPU
//------------------------------------------------------------------------------

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
    this->run(&world_switch);
}

void
vcpu::return_failure()
{
    this->set_rax(FAILURE);
    this->run(&world_switch);
}

void
vcpu::return_and_continue()
{
    this->set_rax(VCPU_OP__RUN_CONTINUE);
    this->run(&world_switch);
}

void
vcpu::return_and_sleep(uint64_t usec)
{
    this->set_rax((usec << 16U) | VCPU_OP__RUN_SLEEP);
    this->run(&world_switch);
}

//------------------------------------------------------------------------------
// Control
//------------------------------------------------------------------------------

bool
vcpu::is_alive() const
{ return !m_killed; }

bool
vcpu::is_killed() const
{ return m_killed; }

bool
vcpu::is_asleep() const
{ return m_asleep; }

bool
vcpu::is_awake() const
{ return !m_asleep; }

void
vcpu::kill()
{ m_killed = true; }

void
vcpu::sleep()
{ m_asleep = true; }

void
vcpu::wake(bfobject *obj)
{
    /// We clear Linux's sti blocking because we are waking from
    /// a hlt instruction. Linux does sti right before the hlt, so
    /// blocking_by_sti is set. If we don't clear it and try to inject
    /// anyway, VM-entry will fail.
    ///

    ::intel_x64::vmcs::guest_interruptibility_state::blocking_by_sti::disable();
    m_asleep = false;

    this->queue_external_interrupt(m_timer_vector);
    this->run(obj);
}

void
vcpu::set_timer_vector(uint64_t vector)
{ m_timer_vector = vector; }

void
vcpu::queue_timer_interrupt()
{ this->queue_external_interrupt(m_timer_vector); }

//------------------------------------------------------------------------------
// LAPIC
//------------------------------------------------------------------------------

uint32_t
vcpu::lapicid() const
{ return m_lapic.id(); }

uint64_t
vcpu::lapic_base() const
{ return m_lapic.base(); }

uint32_t
vcpu::lapic_read(uint32_t indx) const
{ return m_lapic.read(indx); }

void
vcpu::lapic_write(uint32_t indx, uint32_t val)
{ m_lapic.write(indx, val); }

//------------------------------------------------------------------------------
// Resources
//------------------------------------------------------------------------------

std::vector<e820_entry_t> &
vcpu::e820_map()
{ return m_domain->e820_map(); }

domain *
vcpu::dom()
{ return m_domain; }

}
