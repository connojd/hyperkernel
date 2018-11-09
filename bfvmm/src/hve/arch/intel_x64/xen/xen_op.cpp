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

#include <iostream>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/lapic.h>
#include <eapis/hve/arch/intel_x64/time.h>

#include <hve/arch/intel_x64/xen/public/xen.h>
#include <hve/arch/intel_x64/xen/public/event_channel.h>
#include <hve/arch/intel_x64/xen/public/memory.h>
#include <hve/arch/intel_x64/xen/public/version.h>
#include <hve/arch/intel_x64/xen/public/hvm/hvm_op.h>
#include <hve/arch/intel_x64/xen/public/hvm/params.h>
#include <hve/arch/intel_x64/xen/public/arch-x86/cpuid.h>

#include <hve/arch/intel_x64/xen/xen_op.h>
#include <hve/arch/intel_x64/xen/sched_op.h>
#include <hve/arch/intel_x64/xen/evtchn_op.h>
#include "../../../../../../include/gpa_layout.h"

// wrmsr_safe(0xC0000600, dec, 0);
// wrmsr_safe(0xC0000700, hex, 0);

// =============================================================================
// Definitions
// =============================================================================

constexpr auto xen_msr_hypercall_page   = 0xC0000500;
constexpr auto xen_msr_debug_ndec       = 0xC0000600;
constexpr auto xen_msr_debug_nhex       = 0xC0000700;

// =============================================================================
// Macros
// =============================================================================

#define make_delegate(a,b)                                                                          \
    eapis::intel_x64::a::handler_delegate_t::create<xen_op_handler, &xen_op_handler::b>(this)

#define ADD_VMCALL_HANDLER(a)                                                                       \
    m_vcpu->add_vmcall_handler(                                                                     \
        vmcall_handler_delegate(xen_op_handler, a))

#define ADD_CPUID_HANDLER(a,b)                                                                      \
    m_vcpu->add_cpuid_handler(                                                                      \
        a, make_delegate(cpuid_handler, b))

#define EMULATE_CPUID(a,b)                                                                          \
    m_vcpu->emulate_cpuid(                                                                          \
        a, make_delegate(cpuid_handler, b))

#define EMULATE_RDMSR(a,b)                                                                          \
    m_vcpu->emulate_rdmsr(                                                                          \
        a, make_delegate(rdmsr_handler, b))

#define ADD_WRMSR_HANDLER(a,b)                                                                      \
    m_vcpu->add_wrmsr_handler(                                                                      \
        a, make_delegate(wrmsr_handler, b))

#define EMULATE_WRMSR(a,b)                                                                          \
    m_vcpu->emulate_wrmsr(                                                                          \
        a, make_delegate(wrmsr_handler, b))

#define EMULATE_IO_INSTRUCTION(a,b,c)                                                               \
    m_vcpu->emulate_io_instruction(                                                                 \
        a, make_delegate(io_instruction_handler, b), make_delegate(io_instruction_handler, c))

#define ADD_EPT_WRITE_HANDLER(b)                                                                    \
    m_vcpu->add_ept_write_violation_handler(make_delegate(ept_violation_handler, b))

#define ADD_EPT_READ_HANDLER(b)                                                                     \
    m_vcpu->add_ept_read_violation_handler(make_delegate(ept_violation_handler, b))

// =============================================================================
// Implementation
// =============================================================================

namespace hyperkernel::intel_x64
{

static uint64_t tsc_frequency(void);

xen_op_handler::xen_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_evtchn_op{std::make_unique<evtchn_op>(vcpu, this)}
{
    using namespace vmcs_n;

    vcpu->add_run_delegate(
        bfvmm::vcpu::run_delegate_t::create<xen_op_handler, &xen_op_handler::run_delegate>(this)
    );

    vcpu->add_exit_handler(
        handler_delegate_t::create<xen_op_handler, &xen_op_handler::exit_handler>(this)
    );

    EMULATE_WRMSR(xen_msr_hypercall_page, xen_hypercall_page_wrmsr_handler);
    EMULATE_WRMSR(xen_msr_debug_ndec, xen_debug_ndec_wrmsr_handler);
    EMULATE_WRMSR(xen_msr_debug_nhex, xen_debug_nhex_wrmsr_handler);

    EMULATE_CPUID(XEN_CPUID_LEAF(0), xen_cpuid_leaf1_handler);
    EMULATE_CPUID(XEN_CPUID_LEAF(1), xen_cpuid_leaf2_handler);
    EMULATE_CPUID(XEN_CPUID_LEAF(2), xen_cpuid_leaf3_handler);
    EMULATE_CPUID(XEN_CPUID_LEAF(4), xen_cpuid_leaf5_handler);

    ADD_VMCALL_HANDLER(HYPERVISOR_memory_op);
    ADD_VMCALL_HANDLER(HYPERVISOR_xen_version);
    ADD_VMCALL_HANDLER(HYPERVISOR_hvm_op);
    ADD_VMCALL_HANDLER(HYPERVISOR_event_channel_op);
    // ADD_VMCALL_HANDLER(HYPERVISOR_sched_op);

    if (vcpu->is_domU()) {
        vcpu->trap_on_all_io_instruction_accesses();
        vcpu->trap_on_all_rdmsr_accesses();
        vcpu->trap_on_all_wrmsr_accesses();
    }

    this->isolate_msr(::x64::msrs::ia32_star::addr);
    this->isolate_msr(::x64::msrs::ia32_lstar::addr);
    this->isolate_msr(::x64::msrs::ia32_cstar::addr);
    this->isolate_msr(::x64::msrs::ia32_fmask::addr);
    this->isolate_msr(::x64::msrs::ia32_kernel_gs_base::addr);

    if (vcpu->is_dom0()) {
        return;
    }

    vcpu->pass_through_msr_access(::x64::msrs::ia32_pat::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_efer::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_fs_base::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_gs_base::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_cs::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_eip::addr);
    vcpu->pass_through_msr_access(::intel_x64::msrs::ia32_sysenter_esp::addr);

    EMULATE_RDMSR(0xFE, rdmsr_zero_handler);                        // MTRRs not supported
    EMULATE_RDMSR(0x2FF, rdmsr_zero_handler);                       // MTRRs not supported

    EMULATE_RDMSR(::intel_x64::msrs::ia32_apic_base::addr,
                  ia32_apic_base_rdmsr_handler);                    // TODO: use namespace name

    EMULATE_WRMSR(::intel_x64::msrs::ia32_apic_base::addr,
                  ia32_apic_base_wrmsr_handler);                    // TODO: use namespace name

    EMULATE_RDMSR(0x1A0, ia32_misc_enable_rdmsr_handler);           // TODO: use namespace name
    EMULATE_WRMSR(0x1A0, ia32_misc_enable_wrmsr_handler);           // TODO: use namespace name

    ADD_CPUID_HANDLER(0, cpuid_pass_through_handler);
    ADD_CPUID_HANDLER(0x6, cpuid_leaf6_handler);
    ADD_CPUID_HANDLER(0x7, cpuid_leaf7_handler);
    EMULATE_CPUID(0xD, cpuid_zero_handler);
    EMULATE_CPUID(0xF, cpuid_zero_handler);
    EMULATE_CPUID(0x10, cpuid_zero_handler);
    ADD_CPUID_HANDLER(0x15, cpuid_pass_through_handler);            // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x16, cpuid_pass_through_handler);            // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000000, cpuid_pass_through_handler);      // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000001, cpuid_leaf80000001_handler);      // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000007, cpuid_pass_through_handler);      // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000008, cpuid_pass_through_handler);      // TODO: 0 reserved bits

    EMULATE_IO_INSTRUCTION(0xCF8, io_ones_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0xCFC, io_ones_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0xCFD, io_ones_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0xCFE, io_ones_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0xCFF, io_ones_handler, io_ignore_handler);

    this->register_unplug_quirk();

    /// TODO:
    ///
    /// This currently gives the serial device to the guest. At some point we
    /// will need to emulate these instead of passing them through which will
    /// allow the hypervisor and the guest to co-exist. For now this works,
    /// just make sure that the serial settings for the hypervisor and the
    /// guest are identical.
    ///
    vcpu->pass_through_io_accesses(0x3f8);
    vcpu->pass_through_io_accesses(0x3f9);
    vcpu->pass_through_io_accesses(0x3fa);
    vcpu->pass_through_io_accesses(0x3fb);
    vcpu->pass_through_io_accesses(0x3fc);
    vcpu->pass_through_io_accesses(0x3fd);

    this->emulate_rdmsr_x2apic();
    this->emulate_wrmsr_x2apic();


    // m_sched_op = std::make_unique<sched_op>(vcpu, tsc_frequency());
}

/// TODO
///
/// The commented registers are not readable, so we really
/// should inject a #GP
///
void
xen_op_handler::emulate_rdmsr_x2apic()
{
    using namespace ::intel_x64::msrs;

    EMULATE_RDMSR(ia32_x2apic_apicid::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_version::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_tpr::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_ppr::addr, handle_rdmsr_x2apic);
//    EMULATE_RDMSR(ia32_x2apic_eoi::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_ldr::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_svr::addr, handle_rdmsr_x2apic);

    EMULATE_RDMSR(ia32_x2apic_isr0::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_isr1::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_isr2::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_isr3::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_isr4::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_isr5::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_isr6::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_isr7::addr, handle_rdmsr_x2apic);

    EMULATE_RDMSR(ia32_x2apic_tmr0::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_tmr1::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_tmr2::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_tmr3::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_tmr4::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_tmr5::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_tmr6::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_tmr7::addr, handle_rdmsr_x2apic);

    EMULATE_RDMSR(ia32_x2apic_irr0::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_irr1::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_irr2::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_irr3::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_irr4::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_irr5::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_irr6::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_irr7::addr, handle_rdmsr_x2apic);

    EMULATE_RDMSR(ia32_x2apic_esr::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_lvt_cmci::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_icr::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_lvt_timer::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_lvt_thermal::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_lvt_pmi::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_lvt_lint0::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_lvt_lint1::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_lvt_error::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_init_count::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_cur_count::addr, handle_rdmsr_x2apic);
    EMULATE_RDMSR(ia32_x2apic_dcr::addr, handle_rdmsr_x2apic);
//    EMULATE_RDMSR(ia32_x2apic_self_ipi::addr, handle_rdmsr_x2apic);
}

/// TODO
///
/// The commented registers are not writeable, so we really
/// should inject a #GP
///

void
xen_op_handler::emulate_wrmsr_tsc_deadline()
{

}

void
xen_op_handler::emulate_wrmsr_x2apic()
{
    using namespace ::intel_x64::msrs;

//    EMULATE_WRMSR(ia32_x2apic_apicid::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_version::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_tpr::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_ppr::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_eoi::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_ldr::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_svr::addr, handle_wrmsr_x2apic);

//    EMULATE_WRMSR(ia32_x2apic_isr0::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_isr1::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_isr2::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_isr3::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_isr4::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_isr5::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_isr6::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_isr7::addr, handle_wrmsr_x2apic);
//
//    EMULATE_WRMSR(ia32_x2apic_tmr0::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_tmr1::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_tmr2::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_tmr3::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_tmr4::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_tmr5::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_tmr6::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_tmr7::addr, handle_wrmsr_x2apic);
//
//    EMULATE_WRMSR(ia32_x2apic_irr0::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_irr1::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_irr2::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_irr3::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_irr4::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_irr5::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_irr6::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_irr7::addr, handle_wrmsr_x2apic);

    EMULATE_WRMSR(ia32_x2apic_esr::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_lvt_cmci::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_icr::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_lvt_timer::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_lvt_thermal::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_lvt_pmi::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_lvt_lint0::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_lvt_lint1::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_lvt_error::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_init_count::addr, handle_wrmsr_x2apic);
//    EMULATE_WRMSR(ia32_x2apic_cur_count::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_dcr::addr, handle_wrmsr_x2apic);
    EMULATE_WRMSR(ia32_x2apic_self_ipi::addr, handle_wrmsr_x2apic);
}

static uint64_t
tsc_frequency(void)
{
    using namespace ::x64::cpuid;
    using namespace ::intel_x64::cpuid;

    // If we are running on VMWare, frequency information is reported through
    // a different CPUID leaf that is hypervisor specific so we should check
    // to see if we are on VMWare first which returns its results in kHz
    // already for us.
    //
    // If we are not on VMWare, we use CPUID 0x15 to report the TSC frequency
    // which is more accurate than 0x16. There is a quirk with some
    // archiectures in that the crystal clock speed is not reported properly,
    // so that information has to be hard coded.
    //
    // Notes:
    // - An invariant TSC is expected and required
    // - The result of this function is in kHz.
    // - The TSC core ratio is used instead of 0x16 as it is more accurate

    if (!eapis::intel_x64::time::tsc_supported()) {
        throw std::runtime_error("unsupported system: no TSC");
    }

    if (!eapis::intel_x64::time::invariant_tsc_supported()) {
        throw std::runtime_error("unsupported system: TSC is not invariant");
    }

    if (ebx::get(0x40000000) == 0x61774d56) {
        if (auto freq = eax::get(0x40000010); freq != 0) {
            return freq;
        }

        throw std::runtime_error("unsupported system: missing vmware freq");
    }

    auto [denominator, numerator, freq, ignore] =
        ::x64::cpuid::get(0x15, 0, 0, 0);


    if (denominator == 0 || numerator == 0) {
        throw std::runtime_error("unsupported system: missing TSC ratio");
    }

    bfdebug_ndec(0, "TSC ratio", numerator / denominator);
    bfdebug_ndec(0, "TSC (kHz)", 24000 * numerator / denominator);

    if (freq == 0) {
        auto bus = eapis::intel_x64::time::bus_freq_MHz();
        auto tsc = eapis::intel_x64::time::tsc_freq_MHz(bus);
//        auto pet = eapis::intel_x64::time::pet_freq_MHz(tsc);

//        bfdebug_ndec(0, "TSC (kHz)", tsc * 1000);
//        bfdebug_ndec(0, "PET (kHz)", pet * 1000);

        return tsc * 1000;
    }
    else {
        freq /= 1000;
    }

    return freq * numerator / denominator;
}

void
xen_op_handler::run_delegate(bfobject *obj)
{
    // Note:
    //
    // Note that this function is executed on every entry, so we want to
    // limit what we are doing here. This is an expensive function to
    // execute.

    this->update_vcpu_time_info();

    // Note:
    //
    // We don't use the MSR load/store pages as Intel actually states not to
    // use them so that you can use lazy load/store. To make this work we have
    // three different types of MSRs that we have to deal with:
    // - pass through: these are MSRs that are passed through to the guest so
    //   that the guest can read / write to these MSRs and actually change
    //   the physical hardware. An example of this type of MSR is the LSTAR.
    //   Since this type of MSR is changing the hardware, on each world
    //   switch, we have to write these values from the guest to the hardware
    //   so that these values are the proper value before executing the new
    //   vcpu. Since we need to cache these values, we have to watch writes
    //   to these values. Thankfully, writes to these types of MSRs don't
    //   really happen. Also note that these MSRs cannot be used by the VMM
    //   for this to work, which is one reason why Bareflank only used the MSRs
    //   that are natively saved/loaded by the VMCS already using existing
    //   controls. Note that we use the isolate function to handle the MSRs
    //   that are not already in the VMCS. If the MSR is already in the VMCS
    //   we only use the pass through function, as the VMCS will handle
    //   load/store for us automatically.
    // - emulated: these are MSRs that never touch the real hardware. We fake
    //   the contents of these MSRs and all reads and writes go to our fake
    //   MSR value. There are not many of these, and we use these to
    //   communicate the configuration of hardware to a guest vcpu.
    // - load/store: these are MSRs that have to be saved on every exit, and
    //   then restored on every entry. We want to keep this list to a minimum
    //   and for now, the only register that is in this basket is the SWAPGS
    //   msr, as we have no way of seeing writes to it, so have to save its
    //   value on exit, and restore on every world switch. Note that we
    //   handle these MSRs the same as pass through, with the exception that
    //   they need to be stored on exit.

    if (obj != nullptr) {
        for (const auto &msr : m_msrs) {
            ::x64::msrs::set(msr.first, msr.second);
        }
    }
}

bool
xen_op_handler::exit_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    // Note:
    //
    // Note that this function is executed on every exit, so we want to
    // limit what we are doing here. This is an expensive function to
    // execute.
    //
    // Should we add this to the exit/entry asm glue? - CD

    using namespace ::x64::msrs;
    m_msrs[ia32_kernel_gs_base::addr] = ia32_kernel_gs_base::get();

    // Ignored
    return false;
}

// -----------------------------------------------------------------------------
// xAPIC
// -----------------------------------------------------------------------------

bool
xen_op_handler::xapic_handle_write_icr(
    eapis::intel_x64::ept_violation_handler::info_t &info)
{
    using namespace eapis::intel_x64::lapic::icr_low;

    auto dlm = delivery_mode::get(m_icr);
    switch (dlm) {
        case delivery_mode::fixed:
            break;
        default:
            bfalert_nhex(0, "unsupported delivery mode:", dlm);
            return false;
    }

    auto dsh = dest_shorthand::get(m_icr);
    switch (dsh) {
        case dest_shorthand::self: {
            m_vcpu->queue_external_interrupt(vector::get(m_icr));
            m_vcpu->set_icr_idle(m_icr);
//            static bool registered = false;
//            if (!registered) {
//                ADD_EPT_READ_HANDLER(xapic_handle_read);
//                registered = true;
//            }
        }   break;
        default:
            bfalert_nhex(0, "unsupported dest shorthand: ", dsh);
            return false;
    }

    info.ignore_advance = false;
    return true;
}

bool
xen_op_handler::xapic_handle_read(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::ept_violation_handler::info_t &info)
{
    auto hkv = vcpu_cast(vcpu);
    if (bfn::upper(info.gpa) != hkv->lapic_base()) {
        return false;
    }

    auto idx = bfn::lower(info.gpa) >> 2;
    bfdebug_nhex(0, "xapic read", idx << 2);
    bfdebug_subnhex(0, "val", m_vcpu->lapic_read(idx));

    const auto len = ::intel_x64::vmcs::vm_exit_instruction_length::get();
    const auto rip = ::intel_x64::vmcs::guest_rip::get();

    auto itr = m_xapic_rip_cache.find(rip);
    if (itr == m_xapic_rip_cache.end()) {
        auto ump = hkv->map_gva_4k<uint8_t>(rip, len);
        if (!ump) {
            throw std::runtime_error("handle_xapic_write::map_gva_4k failed");
        }

        m_xapic_rip_cache[rip] = std::move(ump);
        itr = m_xapic_rip_cache.find(rip);
    }

    const auto buf = itr->second.get();
    printf("received xapic insn: ");
    for (auto i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
    printf("\n");

    return false;
}

uint64_t
src_op_value(gsl::not_null<vcpu_t *> vcpu, int64_t src_op)
{
    switch (src_op) {
        case hyperkernel::intel_x64::insn_decoder::eax:
            return vcpu->rax() & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::ecx:
            return vcpu->rcx() & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::edx:
            return vcpu->rdx() & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::ebx:
            return vcpu->rbx() & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::esp:
            return vcpu->rsp() & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::ebp:
            return vcpu->rbp() & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::esi:
            return vcpu->rsi() & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::edi:
            return vcpu->rdi() & 0xFFFFFFFFU;
    }

    throw std::invalid_argument("invalid reg");
}

static void print_insn(const unsigned char *buf, size_t len)
{
    for (auto i = 0; i < len; i++) {
        printf("%02x", buf[i]);
    }
}

bool
xen_op_handler::xapic_handle_write(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::ept_violation_handler::info_t &info)
{
    using namespace eapis::intel_x64::lapic;

    auto hkv = vcpu_cast(vcpu);
    if (bfn::upper(info.gpa) != hkv->lapic_base()) {
        return false;
    }

    const auto idx = bfn::lower(info.gpa) >> 2;
    if (idx == eoi::indx) {
        info.ignore_advance = false;
        return true;
    }

    const auto len = ::intel_x64::vmcs::vm_exit_instruction_length::get();
    const auto rip = ::intel_x64::vmcs::guest_rip::get();

    auto itr = m_xapic_rip_cache.find(rip);
    if (itr == m_xapic_rip_cache.end()) {
        auto ump = hkv->map_gva_4k<uint8_t>(rip, len);
        if (!ump) {
            throw std::runtime_error("handle_xapic_write::map_gva_4k failed");
        }

        m_xapic_rip_cache[rip] = std::move(ump);
        itr = m_xapic_rip_cache.find(rip);
    }

    const auto buf = itr->second.get();

    printf("xapic_write: ");
    print_insn(buf, len);

    hyperkernel::intel_x64::insn_decoder dec(buf, len);
    const auto val = src_op_value(vcpu, dec.src_op());
    printf(" value: %08lx\n", val);

    switch (idx) {
        case icr_high::indx:
            m_icr |= (val << 32);
            break;

        case icr_low::indx:
            m_icr |= val;
            return this->xapic_handle_write_icr(info);
    }

    return false;
}

// -----------------------------------------------------------------------------
// MSRs
// -----------------------------------------------------------------------------

void
xen_op_handler::isolate_msr(uint32_t msr)
{
    m_vcpu->pass_through_rdmsr_access(msr);
    ADD_WRMSR_HANDLER(msr, wrmsr_store_handler);

    if (m_vcpu->is_dom0()) {
        m_msrs[msr] = ::x64::msrs::get(msr);
    }
}

bool
xen_op_handler::rdmsr_zero_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0U;
    return true;
}

bool
xen_op_handler::wrmsr_ignore_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
xen_op_handler::rdmsr_pass_through_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
xen_op_handler::wrmsr_pass_through_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
xen_op_handler::wrmsr_store_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_msrs[info.msr] = info.val;
    return true;
}

bool
xen_op_handler::ia32_misc_enable_rdmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);
    using namespace ::intel_x64::msrs;

    info.val = 0;
    return true;
}

bool
xen_op_handler::ia32_misc_enable_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return false;
}

bool
xen_op_handler::ia32_apic_base_rdmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    auto val = m_vcpu->lapic_base();
    ::intel_x64::msrs::ia32_apic_base::bsp::enable(val);
    ::intel_x64::msrs::ia32_apic_base::state::enable_x2apic(val);
    info.val = val;

    return true;
}

bool
xen_op_handler::ia32_apic_base_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    bfalert_info(0, "Unexpected write to IA32_APIC_BASE...halting");

    return false;
}

// We get the *dword* indx into the virtual lapic
//
// See lapic.h in eapis for details
//
static uint64_t indx_to_msr(uint32_t indx)
{
    constexpr const auto x2apic_base = 0x800U;
    return x2apic_base | (indx >> 2U);
}

static uint64_t msr_to_indx(uint32_t msr)
{ return (msr & 0xFFU) << 2U; }


bool
xen_op_handler::handle_rdmsr_x2apic(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_vcpu->lapic_read(msr_to_indx(info.msr));
    return true;
}

bool
xen_op_handler::handle_wrmsr_x2apic(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    using eapis::intel_x64;

    const auto indx = msr_to_indx(info.msr);
    switch (indx) {

    // We greedily assume the guest wrote a 0
    // (the only value allowed) and return immediately
    //
    case lapic::eoi::indx:
        return true;

    case lapic::lvt::timer::indx:
        return this->handle_wrmsr_lvt_timer(vcpu, info);

    case lapic::icr_high::indx:
        vcpu->lapic_write(indx, info.val);
        return true;

    case lapic::icr_low::indx:
        return this->handle_wrmsr_icr(vcpu, info);

    case lapic::self_ipi::indx:
        vcpu->queue_external_interrupt(info.val & 0xFFU);
        return true;

    default:
        bfalert_info(0, "Unexpected x2apic write");
        bfalert_subnhex(0, "msr", info.msr);
        bfalert_subnhex(0, "val", info.val);
        bfalert_subnhex(0, "dword indx", indx);
        bfalert_subnhex(0, "byte indx", indx << 2);
        return false;
    }
}

bool
xen_op_handler::handle_wrmsr_icr(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    using namespace eapis::intel_x64::lapic;

    const auto low = info.val;

    switch (icr_low::delivery_mode::get(low)) {
    case icr_low::delivery_mode::fixed:
        break;

    default:
        bfalert_info(0, "Unexpected IPI delivery mode");
        icr_high::dump(0, vcpu->lapic_read(icr_high::indx));
        icr_low::dump(0, low);
        return false;
    }

    vcpu->lapic_write(icr_low::indx, low);

    // Right now we only have one vcpu, so we skip the destination
    // calculations. Also, a sane and well-behaved guest would never
    // take this path, they would use the self IPI register explicitly
    //
    icr_high::dump(0, vcpu->lapic_read(icr_high::indx));
    icr_low::dump(0, low);

    vcpu->queue_external_interrupt(vector::get(low));

    return true;
}

bool
xen_op_handler::handle_wrmsr_lvt_timer(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    using namespace eapis::intel_x64::lapic::lvt;

    auto mode = timer::mode::get(info.val);

    switch (mode) {
    case timer::mode::tsc_deadline:
        break;

    default:
        bfalert_info(0, "Unexpected LVT timer mode");
        timer::dump(0, info.val);
        return false;
    }

    vcpu->lapic_write(timer::indx, info.val);
//    EMULATE_WRMSR(indx_to_msr(timer::indx), emulate_wrmsr_tsc_deadline);

    return true;
}

static void
vmx_init_hypercall_page(uint8_t *hypercall_page)
{
    auto page = gsl::span(hypercall_page, 0x1000);

    for (uint8_t i = 0; i < 55; i++) {
        auto entry = page.subspan(i * 32, 32);

        entry[0] = 0xB8U;
        entry[1] = i;
        entry[2] = 0U;
        entry[3] = 0U;
        entry[4] = 0U;
        entry[5] = 0x0FU;
        entry[6] = 0x01U;
        entry[7] = 0xC1U;
        entry[8] = 0xC3U;
    }
}

bool
xen_op_handler::xen_hypercall_page_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    auto map = vcpu_cast(vcpu)->map_gpa_4k<uint8_t>(info.val);
    vmx_init_hypercall_page(map.get());

    return true;
}

bool
xen_op_handler::xen_debug_ndec_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfdebug_ndec(0, "debug", info.val);
    return true;
}

bool
xen_op_handler::xen_debug_nhex_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfdebug_nhex(0, "debug", info.val);
    return true;
}

// -----------------------------------------------------------------------------
// CPUID
// -----------------------------------------------------------------------------

bool
xen_op_handler::cpuid_zero_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0U;
    info.rbx = 0U;
    info.rcx = 0U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::cpuid_pass_through_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

bool
xen_op_handler::cpuid_leaf6_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // Diables all power management, minus leaving ARAT turned on. The guest
    // should not attempt to maintain power management as that will be done
    // by the host OS.

    info.rax &= 0x4U;
    info.rbx = 0U;
    info.rcx = 0U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::cpuid_leaf7_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // Diables the following features:
    //
    // EBX:
    // - SGX                no plans to support
    // - AVX2               need to properly emulate XSAVE/XRESTORE
    // - INVPCID            need to properly emulate PCID
    // - RTM                no plans to support
    // - RDT-M              no plans to support
    // - MPX                no plans to support
    // - RDT-A              no plans to support
    // - AVX512F            need to properly emulate XSAVE/XRESTORE
    // - AVX512DQ           need to properly emulate XSAVE/XRESTORE
    // - AVX512_IFMA        need to properly emulate XSAVE/XRESTORE
    // - Processor Trace    no plans to support
    // - AVX512PF           need to properly emulate XSAVE/XRESTORE
    // - AVX512ER           need to properly emulate XSAVE/XRESTORE
    // - AVX512CD           need to properly emulate XSAVE/XRESTORE
    // - SHA                need to properly emulate XSAVE/XRESTORE
    // - AVX512BW           need to properly emulate XSAVE/XRESTORE
    // - AVX512VL           need to properly emulate XSAVE/XRESTORE
    //
    // ECX:
    // - PREFETCHWT1        no plans to support
    // - AVX512_VBMI        need to properly emulate XSAVE/XRESTORE
    // - UMIP               ??? Might be able to support, not sure
    // - PKU                ??? Might be able to support, not sure
    // - OSPKE              ??? Might be able to support, not sure
    // - MAWAU              no plans to support
    // - SGX_LC             no plans to support

    if (info.rcx != 0) {
        info.rax = 0U;
        info.rbx = 0U;
        info.rcx = 0U;
        info.rdx = 0U;
    }

    info.rax = 1U;
    info.rbx &= 0x19C23DBU;
    info.rcx &= 0x0400000U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::cpuid_leaf80000001_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // Diables the following features:
    //
    // EDX:
    // - 1-GByte Pages      no plans to support

    info.rbx = 0U;
    info.rcx &= 0x121U;
    info.rdx &= 0x18100800U;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf1_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = XEN_CPUID_LEAF(5);
    info.rbx = XEN_CPUID_SIGNATURE_EBX;
    info.rcx = XEN_CPUID_SIGNATURE_ECX;
    info.rdx = XEN_CPUID_SIGNATURE_EDX;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf2_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0x00040B00U; // 4.11
    info.rbx = 0U;
    info.rcx = 0U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf3_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 1U;
    info.rbx = xen_msr_hypercall_page;
    info.rcx = 0U;
    info.rdx = 0U;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf5_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 0U;
    info.rax |= XEN_HVM_CPUID_APIC_ACCESS_VIRT;
    // info.rax |= XEN_HVM_CPUID_X2APIC_VIRT;           // Need to support emulated VT-d first
    // info.rax |= XEN_HVM_CPUID_IOMMU_MAPPINGS;        // Need to support emulated VT-d first
    info.rax |= XEN_HVM_CPUID_VCPU_ID_PRESENT;
    info.rax |= XEN_HVM_CPUID_DOMID_PRESENT;
    info.rbx = m_vcpu->lapicid();
    info.rcx = m_vcpu->domid();
    info.rdx = 0U;

    return true;
}

// -----------------------------------------------------------------------------
// IO Instruction
// -----------------------------------------------------------------------------

bool
xen_op_handler::io_zero_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
xen_op_handler::io_ones_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFFFFFFFFFF;
    return true;
}

bool
xen_op_handler::io_ignore_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    return true;
}

// -----------------------------------------------------------------------------
// HYPERVISOR_memory_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_memory_op(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_memory_op) {
        return false;
    }

    switch (vcpu->rdi()) {
        case XENMEM_add_to_physmap:
            this->XENMEM_add_to_physmap_handler(vcpu);
            return true;

        case XENMEM_memory_map:
            this->XENMEM_memory_map_handler(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_memory_op opcode");
}

void
xen_op_handler::XENMEM_add_to_physmap_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto xen_add_to_physmap_arg =
            vcpu->map_arg<xen_add_to_physmap>(
                vcpu->rsi()
            );

        if (xen_add_to_physmap_arg->domid != DOMID_SELF) {
            throw std::runtime_error("unsupported domid");
        }

        switch (xen_add_to_physmap_arg->space) {
            case XENMAPSPACE_shared_info:
                m_shared_info =
                    vcpu->map_gpa_4k<shared_info_t>(
                        xen_add_to_physmap_arg->gpfn << ::x64::pt::page_shift
                    );
                this->reset_vcpu_time_info();
                break;

            default:
                throw std::runtime_error("XENMEM_add_to_physmap: unknown space");
        };

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::XENMEM_memory_map_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto map = vcpu->map_arg<xen_memory_map>(vcpu->rsi());

        if (map->nr_entries < vcpu->e820_map().size()) {
            throw std::runtime_error("guest E820 too small");
        }

        auto addr = map->buffer.p;
        auto size = map->nr_entries;

        auto e820 = vcpu->map_gva_4k<e820_entry_t>(addr, size);
        auto e820_view = gsl::span<e820_entry_t>(e820.get(), size);

        map->nr_entries = 0;
        for (const auto &entry : vcpu->e820_map()) {
            e820_view[map->nr_entries].addr = entry.addr;
            e820_view[map->nr_entries].size = entry.size;
            e820_view[map->nr_entries].type = entry.type;
            map->nr_entries++;
        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

// -----------------------------------------------------------------------------
// HYPERVISOR_xen_version
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_xen_version(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_xen_version) {
        return false;
    }

    switch (vcpu->rdi()) {
        case XENVER_get_features:
            this->XENVER_get_features_handler(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_xen_version opcode");
}

void
xen_op_handler::XENVER_get_features_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto info =
            vcpu->map_arg<xen_feature_info>(
                vcpu->rsi()
            );

        if (info->submap_idx >= XENFEAT_NR_SUBMAPS) {
            throw std::runtime_error("unknown Xen features submap");
        }

        info->submap = 0;
        info->submap |= (1 << XENFEAT_writable_page_tables);
        info->submap |= (1 << XENFEAT_writable_descriptor_tables);
        info->submap |= (1 << XENFEAT_auto_translated_physmap);
        info->submap |= (1 << XENFEAT_supervisor_mode_kernel);
        info->submap |= (1 << XENFEAT_pae_pgdir_above_4gb);
        info->submap |= (1 << XENFEAT_mmu_pt_update_preserve_ad);
        info->submap |= (1 << XENFEAT_highmem_assist);
        info->submap |= (1 << XENFEAT_gnttab_map_avail_bits);
        info->submap |= (1 << XENFEAT_hvm_callback_vector);
        // info->submap |= (1 << XENFEAT_hvm_safe_pvclock);
        // info->submap |= (1 << XENFEAT_hvm_pirqs);
        info->submap |= (1 << XENFEAT_dom0);
        info->submap |= (1 << XENFEAT_memory_op_vnode_supported);
        // info->submap |= (1 << XENFEAT_ARM_SMCCC_supported);
        info->submap |= (1 << XENFEAT_linux_rsdp_unrestricted);

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

// -----------------------------------------------------------------------------
// HYPERVISOR_sched_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_sched_op(gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_sched_op) {
        return false;
    }

    switch (vcpu->rdi()) {
        case SCHEDOP_yield:
            this->SCHEDOP_yield_handler(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error(
        "unknown HYPERVISOR_sched_op: " + std::to_string(vcpu->rdi()));
}

void
xen_op_handler::SCHEDOP_yield_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        m_sched_op->handle_yield(vcpu);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

// -----------------------------------------------------------------------------
// HYPERVISOR_event_channel_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_event_channel_op(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_event_channel_op) {
        return false;
    }

    switch (vcpu->rdi()) {
        case EVTCHNOP_init_control:
            this->EVTCHNOP_init_control_handler(vcpu);
            return true;

        case EVTCHNOP_send:
            this->EVTCHNOP_send_handler(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_event_channel_op: " +
                             std::to_string(vcpu->rdi()));
}

void
xen_op_handler::EVTCHNOP_init_control_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<evtchn_init_control_t>(vcpu->rsi());
        m_evtchn_op->init_control(arg.get());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::EVTCHNOP_send_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<evtchn_send_t>(vcpu->rsi());
        m_evtchn_op->send(arg.get());
        vcpu->set_rax(FAILURE);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

// -----------------------------------------------------------------------------
// HYPERVISOR_hvm_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_hvm_op(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_hvm_op) {
        return false;
    }

    switch (vcpu->rdi()) {
        case HVMOP_set_param:
            this->HVMOP_set_param_handler(vcpu);
            return true;

        case HVMOP_get_param:
            this->HVMOP_get_param_handler(vcpu);
            return true;

        case HVMOP_pagetable_dying:
            this->HVMOP_pagetable_dying_handler(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_hvm_op opcode");
}

inline static void
verify_callback_via(uint64_t via)
{
    const auto from = 56U;
    const auto type = (via & HVM_PARAM_CALLBACK_IRQ_TYPE_MASK) >> from;

    if (type != HVM_PARAM_CALLBACK_TYPE_VECTOR) {
        throw std::invalid_argument(
            "unsupported callback via type: " + std::to_string(via)
        );
    }
}

void
xen_op_handler::HVMOP_set_param_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg =
            vcpu->map_arg<xen_hvm_param_t>(vcpu->rsi());

        switch (arg->index) {
            case HVM_PARAM_CALLBACK_IRQ:
                verify_callback_via(arg->value);
                m_callback_via = arg->value & 0xFF;
                vcpu->set_rax(SUCCESS);
                break;

            default:
                bfalert_info(0, "Unsupported HVM param:");
                bfalert_subnhex(0, "domid", arg->domid);
                bfalert_subnhex(0, "index", arg->index);
                bfalert_subnhex(0, "value", arg->value);
                vcpu->set_rax(FAILURE);
                break;
        };
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::HVMOP_get_param_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg =
            vcpu->map_arg<xen_hvm_param_t>(vcpu->rsi());

        switch (arg->index) {
            case HVM_PARAM_CONSOLE_EVTCHN:
                arg->value = 1;
                break;

            case HVM_PARAM_CONSOLE_PFN: {
                m_console = vcpu->map_gpa_4k<uint8_t>(CONSOLE_GPA);
                arg->value = CONSOLE_GPA >> x64::pt::page_shift;
                break;
            }

            default: {
                bfdebug_info(0, "HVMOP_get_param: unknown");
                bfdebug_subnhex(0, "domid", arg->domid);
                bfdebug_subnhex(0, "index", arg->index);

                vcpu->set_rax(FAILURE);
                return;
            }
        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::HVMOP_pagetable_dying_handler(
    gsl::not_null<vcpu *> vcpu)
{
    bfignored(vcpu);
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

void
xen_op_handler::reset_vcpu_time_info()
{
    expects(m_shared_info);
    m_tsc_frequency = tsc_frequency();

    /// The equation for tsc_to_system_mul is the following:
    /// - tsc_to_system_mul = (10^9 << 32) / (CPU freq Hz)
    ///
    /// This can be found in xen.h. In the vcpu_info page. tsc_shift and
    /// tsc_to_system_mul are related if you work the formula out. As one
    /// increases, the other must decrease, which is used for handling
    /// drifting in time and preventing resolution issues with the TSC.
    /// Since we require an invarinat TSC, this shift is not needed so it is
    /// set to 0.
    ///

    constexpr const uint64_t GHz = 10e9;
    auto &info = m_shared_info->vcpu_info[0].time;

    info.tsc_shift = 0;
    info.tsc_to_system_mul = (GHz << 32) / (m_tsc_frequency * 1000);
    info.flags = XEN_PVCLOCK_TSC_STABLE_BIT;
}

void
xen_op_handler::update_vcpu_time_info()
{
    if (!m_shared_info) {
        return;
    }

    constexpr const uint64_t us = 10e6;
    auto &info = m_shared_info->vcpu_info[0].time;

    // The xen.h comments suggest that we need to flip the version to prevent
    // races, although its not clear what type of races could occur if this
    // information is vCPU specific (since the vCPU that should be reading
    // this is not active while the VMM is modifying the fields). Either way
    // we do it.
    //
    // Note that we do our calculations using MHz and not kHz. The reason is
    // even with a 64bit number, we run the risk of overflowing with kHz.
    // The issue with using MHz is the CPU frequency is cut off, which could
    // result in a small amount of drift, since the CPU frequency likely
    // granularity extends to the kHz level.
    //

    info.version = 1;
    info.tsc_timestamp = ::x64::read_tsc::get();
    info.system_time = (info.tsc_timestamp * 1000) / (m_tsc_frequency / 1000);
    info.version = 0;
}

shared_info_t *
xen_op_handler::shared_info()
{ return m_shared_info.get(); }

// -----------------------------------------------------------------------------
// Quirks
// -----------------------------------------------------------------------------

void
xen_op_handler::register_unplug_quirk()
{
    /// Quirk
    ///
    /// At some point, the Linux kernel might attempt to unplug QEMU by
    /// sending port IO requests to it over the port XEN_IOPORT_BASE which
    /// is defined as port 0x10. The problem is, in PVH QEMU doesn't exist,
    /// so there is nobody to send these port IO requests to. Xen itself also
    /// doesn't define these ports, nor does it really understand what they
    /// are (which raises some security concerns). Here we simply ignore
    /// these requests. For more information, see the following:
    ///
    /// http://lkml.iu.edu/hypermail//linux/kernel/1003.0/01368.html
    ///

    constexpr const auto XEN_IOPORT_BASE = 0x10;
    EMULATE_IO_INSTRUCTION(XEN_IOPORT_BASE, io_zero_handler, io_ignore_handler);
}

}
