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

#include <bfgpalayout.h>
#include <hve/arch/intel_x64/lapic.h>
#include <hve/arch/intel_x64/iommu.h>
#include <hve/arch/intel_x64/vcpu.h>

bool shootdown_on = false;
bool ept_ready = false;
uintptr_t invalid_eptp = 0;
std::array<bool, 3> shootdown_ready;

//------------------------------------------------------------------------------
// Fault Handlers
//------------------------------------------------------------------------------

static bool
hk_cpuid_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("cpuid_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
hk_rdmsr_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("rdmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
hk_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("wrmsr_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
hk_io_instruction_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("io_instruction_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

static bool
hk_ept_violation_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    vcpu->halt("ept_violation_handler executed. unsupported!!!");

    // Unreachable
    return true;
}

extern "C" void _nmi(void) noexcept;

//------------------------------------------------------------------------------
// Implementation
//------------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

vcpu::~vcpu()
{
//    if (this->dom()->is_ndvm()) {
////        g_iommu->disable();
//    }
}

vcpu::vcpu(
    vcpuid::type id,
    gsl::not_null<domain *> domain
) :
    eapis::intel_x64::vcpu{
        id, domain->global_state()
    },

    m_domain{domain},
    m_lapic{this},

    m_external_interrupt_handler{this},
    m_vmcall_handler{this},

    m_vmcall_domain_op_handler{this},
    m_vmcall_run_op_handler{this},
    m_vmcall_vcpu_op_handler{this},

    m_xen_op_handler{this, domain}
{
    if (this->is_dom0()) {
        this->write_dom0_guest_state(domain);
    }
    else {
        if (this->dom()->is_ndvm()) {
            vtd::ndvm_vcpu_id = id;
        }
        this->write_domU_guest_state(domain);
    }

// NOTE: this was for TLB shootdown when we were remapping 2M -> 4K in dom0
//    this->set_nmi_handler(_nmi);
//
//    using namespace vmcs_n::exit_reason;
//    this->add_handler(basic_exit_reason::exception_or_non_maskable_interrupt,
//        ::handler_delegate_t::create<vcpu, &vcpu::handle_nmi_exit>(this)
//    );

//    using namespace ::intel_x64::msrs;
//    auto msr = ia32_apic_base::get();
//    expects(ia32_apic_base::state::get(msr) == ia32_apic_base::state::xapic);
//
//    auto hpa = ia32_apic_base::apic_base::get(msr);
//    auto ptr = this->map_hpa_4k<uint8_t>(hpa);
//    auto reg = *reinterpret_cast<uint32_t *>(ptr.get() + 0x20);
//    m_apic_id = reg >> 24;
//    bfdebug_subnhex(0, "physical apic id", m_apic_id);
}

//------------------------------------------------------------------------------
// Setup
//------------------------------------------------------------------------------

void
vcpu::write_dom0_guest_state(domain *domain)
{
    this->set_eptp(domain->ept());
    g_visr->enable(this);
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

    unsigned es_index = 3;
    unsigned cs_index = 2;
    unsigned ss_index = 3;
    unsigned ds_index = 3;
    unsigned fs_index = 3;
    unsigned gs_index = 3;
    unsigned tr_index = 4;

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

    // PAT set to WB
    guest_ia32_pat::set(0x0606060606060606);

    guest_rflags::set(2);
    vmcs_link_pointer::set(0xFFFFFFFFFFFFFFFF);

    m_lapic.init();

    using namespace primary_processor_based_vm_execution_controls;
    hlt_exiting::enable();
    rdpmc_exiting::enable();

    using namespace secondary_processor_based_vm_execution_controls;
    enable_invpcid::disable();
    enable_xsaves_xrstors::disable();

    this->set_rip(domain->entry());
    this->set_rbx(XEN_START_INFO_PAGE_GPA);

    this->add_default_cpuid_handler(
        ::handler_delegate_t::create<hk_cpuid_handler>()
    );

    this->add_default_wrmsr_handler(
        ::handler_delegate_t::create<hk_wrmsr_handler>()
    );

    this->add_default_rdmsr_handler(
        ::handler_delegate_t::create<hk_rdmsr_handler>()
    );

    this->add_default_io_instruction_handler(
        ::handler_delegate_t::create<hk_io_instruction_handler>()
    );

    this->add_default_ept_read_violation_handler(
        ::handler_delegate_t::create<hk_ept_violation_handler>()
    );

    this->add_default_ept_write_violation_handler(
        ::handler_delegate_t::create<hk_ept_violation_handler>()
    );

    this->add_default_ept_execute_violation_handler(
        ::handler_delegate_t::create<hk_ept_violation_handler>()
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
vcpu::return_hlt()
{
    this->set_rax(__enum_run_op__hlt);
    this->run(&world_switch);
}

void
vcpu::return_fault(uint64_t error)
{
    this->set_rax((error << 4) | __enum_run_op__fault);
    this->run(&world_switch);
}

void
vcpu::return_resume_after_interrupt()
{
    this->set_rax(__enum_run_op__resume_after_interrupt);
    this->run(&world_switch);
}

void
vcpu::return_yield(uint64_t usec)
{
    this->set_rax((usec << 4) | __enum_run_op__yield);
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

void
vcpu::kill()
{ m_killed = true; }

void
vcpu::set_timer_vector(uint64_t vector)
{ m_timer_vector = vector; }

void
vcpu::queue_timer_interrupt()
{ this->queue_external_interrupt(m_timer_vector); }

//------------------------------------------------------------------------------
// APIC
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

//------------------------------------------------------------------------------
// Fault
//------------------------------------------------------------------------------

/// TODO:
///
/// We still need to get the exception handler in the base hypervisor to
/// use this function instead of just calling halt() so that we can recover
/// even if an exception fires in the hypervisor.
///

void
vcpu::halt(const std::string &str)
{
    this->dump(("halting vcpu: " + str).c_str());

    if (auto parent_vcpu = this->parent_vcpu()) {

        bferror_lnbr(0);
        bferror_info(0, "child vcpu being killed");
        bferror_lnbr(0);

        parent_vcpu->load();
        parent_vcpu->return_fault();
    }
    else {
        ::x64::pm::stop();
    }
}

// Note that the NMI handlers override the base behavior of injecting
// the NMI into the guest. This will work for windows sans reboot, but
// will potentially cause performance issues in linux because they deliver
// perf interrupts in NMI mode.

// VM-exit entry point
bool
vcpu::handle_nmi_exit(gsl::not_null<bfvmm::intel_x64::vcpu *> vcpu)
{
    bfignored(vcpu);
//    bfdebug_info(0, "NMI exit handler");

    if (shootdown_on) {
        this->shootdown();
    }

    return true;
}

// IDT entry point
extern "C" void hk_nmi_handler(void *vcpu) noexcept
{
    auto hkv = (hyperkernel::intel_x64::vcpu *)vcpu;
//    bfdebug_info(0, "NMI idt handler");

    if (shootdown_on) {
        hkv->shootdown();
    }
}

void
vcpu::shootdown()
{
    expects(this->id() < shootdown_ready.size());
    shootdown_ready[this->id()] = true;

    while (!ept_ready) {
        ::intel_x64::pause();
    }

//    bfdebug_nhex(0, "TLB shootdown:", invalid_eptp);
    ::intel_x64::vmx::invept_global();
}

}
