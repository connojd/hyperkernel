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
#include <hve/arch/x64/pci.h>
#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/lapic.h>
#include <hve/arch/intel_x64/vtd/vtd_sandbox.h>
#include <eapis/hve/arch/intel_x64/time.h>

#include <hve/arch/intel_x64/xen/public/xen.h>
#include <hve/arch/intel_x64/xen/public/event_channel.h>
#include <hve/arch/intel_x64/xen/public/memory.h>
#include <hve/arch/intel_x64/xen/public/version.h>
#include <hve/arch/intel_x64/xen/public/vcpu.h>
#include <hve/arch/intel_x64/xen/public/hvm/hvm_op.h>
#include <hve/arch/intel_x64/xen/public/hvm/params.h>
#include <hve/arch/intel_x64/xen/public/arch-x86/cpuid.h>

#include <hve/arch/intel_x64/xen/xen_op.h>
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

#define ADD_RDMSR_HANDLER(a,b)                                                                      \
    m_vcpu->add_rdmsr_handler(                                                                      \
        a, make_delegate(rdmsr_handler, b))

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

#define ADD_VMX_PET_HANDLER(b) \
    m_vcpu->add_vmx_preemption_timer_handler(make_delegate(vmx_preemption_timer_handler, b))

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
    m_evtchn_op{std::make_unique<evtchn_op>(vcpu, this)},
    m_gnttab_op{std::make_unique<gnttab_op>(vcpu, this)}
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
    ADD_VMCALL_HANDLER(HYPERVISOR_grant_table_op);
    ADD_VMCALL_HANDLER(HYPERVISOR_hvm_op);
    ADD_VMCALL_HANDLER(HYPERVISOR_event_channel_op);
    ADD_VMCALL_HANDLER(HYPERVISOR_vcpu_op);

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

    // We effectively pass this through to the guest already
    // through the eapis::intel_x64::timer::tsc_freq_MHz
    vcpu->pass_through_msr_access(::intel_x64::msrs::platform_info::addr);

    EMULATE_RDMSR(0x34, rdmsr_zero_handler);
    EMULATE_RDMSR(0x64E, rdmsr_zero_handler);

    EMULATE_RDMSR(0x140, rdmsr_zero_handler);
    EMULATE_WRMSR(0x140, wrmsr_ignore_handler);

    EMULATE_RDMSR(::intel_x64::msrs::ia32_apic_base::addr,
                  ia32_apic_base_rdmsr_handler);

    EMULATE_WRMSR(::intel_x64::msrs::ia32_apic_base::addr,
                  ia32_apic_base_wrmsr_handler);

    ADD_RDMSR_HANDLER(0x1A0, ia32_misc_enable_rdmsr_handler);       // TODO: use namespace name
    EMULATE_WRMSR(0x1A0, ia32_misc_enable_wrmsr_handler);           // TODO: use namespace name
    EMULATE_WRMSR(0x6e0, handle_tsc_deadline);

    ADD_CPUID_HANDLER(0x0, cpuid_pass_through_handler);
    ADD_CPUID_HANDLER(0x1, cpuid_leaf1_handler);
    ADD_CPUID_HANDLER(0x2, cpuid_pass_through_handler);             // Passthrough cache info
    ADD_CPUID_HANDLER(0x4, cpuid_leaf4_handler);
    ADD_CPUID_HANDLER(0x6, cpuid_leaf6_handler);
    ADD_CPUID_HANDLER(0x7, cpuid_leaf7_handler);

    EMULATE_CPUID(0xA, cpuid_zero_handler);
    EMULATE_CPUID(0xB, cpuid_zero_handler);
    EMULATE_CPUID(0xD, cpuid_zero_handler);
    EMULATE_CPUID(0xF, cpuid_zero_handler);
    EMULATE_CPUID(0x10, cpuid_zero_handler);

    ADD_CPUID_HANDLER(0x15, cpuid_leaf15_handler);            // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x16, cpuid_pass_through_handler);            // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000000, cpuid_pass_through_handler);      // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000001, cpuid_leaf80000001_handler);      // TODO: 0 reserved bits

    ADD_CPUID_HANDLER(0x80000002, cpuid_pass_through_handler);      // brand str cont. TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000003, cpuid_pass_through_handler);      // brand str cont. TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000004, cpuid_pass_through_handler);      // brand str cont. TODO: 0 reserved bits

    ADD_CPUID_HANDLER(0x80000007, cpuid_pass_through_handler);      // TODO: 0 reserved bits
    ADD_CPUID_HANDLER(0x80000008, cpuid_pass_through_handler);      // TODO: 0 reserved bits

    EMULATE_IO_INSTRUCTION(0xCF8, handle_cf8_in, handle_cf8_out);
    EMULATE_IO_INSTRUCTION(0xCFB, handle_cfb_in, handle_cfb_out);
    EMULATE_IO_INSTRUCTION(0xCFC, handle_cfc_in, handle_cfc_out);
    EMULATE_IO_INSTRUCTION(0xCFD, handle_cfd_in, handle_cfd_out);
    EMULATE_IO_INSTRUCTION(0xCFE, handle_cfe_in, handle_cfe_out);

    /// ACPI SCI interrupt trigger mode
    EMULATE_IO_INSTRUCTION(0x4D0, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0x4D1, io_zero_handler, io_ignore_handler);

    /// NMI assertion
    EMULATE_IO_INSTRUCTION(0x70, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0x71, io_zero_handler, io_ignore_handler);

    EMULATE_IO_INSTRUCTION(0x2F9, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0x3FE, io_zero_handler, io_ignore_handler);

    /// Ports used for TSC calibration against the PIT. See
    /// arch/x86/kernel/tsc.c:pit_calibrate_tsc for detail.
    /// Note that these ports are accessed on the Intel NUC.
    ///
    vcpu->pass_through_io_accesses(0x42);
    vcpu->pass_through_io_accesses(0x43);
    vcpu->pass_through_io_accesses(0x61);

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
    vcpu->pass_through_io_accesses(0xEFF0);
    vcpu->pass_through_io_accesses(0xEFF1);
    vcpu->pass_through_io_accesses(0xEFF2);
    vcpu->pass_through_io_accesses(0xEFF3);
    vcpu->pass_through_io_accesses(0xEFF4);
    vcpu->pass_through_io_accesses(0xEFF5);
    vcpu->pass_through_io_accesses(0xEFF8);
    vcpu->pass_through_io_accesses(0xEFF9);
    vcpu->pass_through_io_accesses(0xEFFA);
    vcpu->pass_through_io_accesses(0xEFFB);
    vcpu->pass_through_io_accesses(0xEFFC);
    vcpu->pass_through_io_accesses(0xEFFD);

    ADD_EPT_WRITE_HANDLER(ioapic_handle_write);
    ADD_EPT_WRITE_HANDLER(xapic_handle_write);
    EMULATE_CPUID(0xBF00, cpuid_ack_handler);

    m_pet_shift = ::intel_x64::msrs::ia32_vmx_misc::preemption_timer_decrement::get();
    m_tsc_freq_khz = tsc_frequency();

    m_vcpu->add_handler(
        exit_reason::basic_exit_reason::hlt,
        ::handler_delegate_t::create<xen_op_handler, &xen_op_handler::handle_hlt>(this)
    );
}

static inline bool
vmware_guest(void)
{
    return ::x64::cpuid::ebx::get(0x40000000) == 0x61774d56;
}

static uint64_t
tsc_frequency(void)
{
    using namespace ::x64::cpuid;
    using namespace ::intel_x64::cpuid;
    using namespace ::eapis::intel_x64::time;

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

    if (!tsc_supported()) {
        throw std::runtime_error("unsupported system: no TSC");
    }

    if (!invariant_tsc_supported()) {
        throw std::runtime_error("unsupported system: TSC is not invariant");
    }

    if (vmware_guest()) {
        if (auto freq = eax::get(0x40000010); freq != 0) {
            return freq;
        }

        throw std::runtime_error("unsupported system: missing vmware freq");
    }

    auto [denominator, numerator, freq, ignore] =
        ::x64::cpuid::get(0x15, 0, 0, 0);

    if (denominator == 0 || numerator == 0 || freq == 0) {
        return tsc_freq_MHz(bus_freq_MHz()) * 1000;
    }

    freq /= 1000;
    return freq * numerator / denominator;
}

// -----------------------------------------------------------------------------
// PET
// -----------------------------------------------------------------------------

bool
xen_op_handler::handle_vmx_pet(gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);

    m_vcpu->queue_timer_interrupt();
    m_vcpu->disable_vmx_preemption_timer();

    return true;
}

// -----------------------------------------------------------------------------
// HLT
// -----------------------------------------------------------------------------

bool
xen_op_handler::handle_hlt(gsl::not_null<vcpu_t *> vcpu)
{
    expects(m_tsc_freq_khz > 1000U);
    advance(vcpu);

    const auto pet_ticks = m_vcpu->get_vmx_preemption_timer();
    const auto tsc_ticks = pet_ticks << m_pet_shift;
    const auto usec = tsc_ticks / (m_tsc_freq_khz / 1000U);

    /// We clear Linux's sti blocking because we are sleeping from
    /// a hlt instruction. Linux does sti right before the hlt, so
    /// blocking_by_sti is set. If we don't clear it and try to inject
    /// later, VM-entry will fail.
    ///

    ::intel_x64::vmcs::guest_interruptibility_state::blocking_by_sti::disable();
    m_vcpu->disable_vmx_preemption_timer();
    m_vcpu->queue_timer_interrupt();
    m_vcpu->parent_vcpu()->load();
    m_vcpu->parent_vcpu()->return_and_sleep(usec);

    // Unreachable
    return true;
}

void
xen_op_handler::run_delegate(bfobject *obj)
{
    // Note:
    //
    // Note that this function is executed on every entry, so we want to
    // limit what we are doing here. This is an expensive function to
    // execute.

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

    using namespace ::x64::msrs;
    using namespace ::intel_x64::vmcs;

    m_msrs[ia32_kernel_gs_base::addr] = ia32_kernel_gs_base::get();

    // Ignored
    return false;
}

// -----------------------------------------------------------------------------
// xAPIC
// -----------------------------------------------------------------------------

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

void
xen_op_handler::xapic_handle_write_icr(uint64_t low)
{
    using namespace eapis::intel_x64::lapic;

    const auto dlm = icr_low::delivery_mode::get(low);
    switch (dlm) {
        case icr_low::delivery_mode::fixed:
            break;
        default:
            if (icr_low::level::is_disabled(low)) {
                return;
            }
            bfalert_nhex(0, "unsupported delivery mode:", dlm);
            icr_low::dump(0, low);
            return;
    }

    auto dsh = icr_low::dest_shorthand::get(low);
    switch (dsh) {
        case icr_low::dest_shorthand::self:
            m_vcpu->queue_external_interrupt(icr_low::vector::get(low));
            m_vcpu->lapic_write(icr_low::indx, low);
            break;
        default:
            bfalert_nhex(0, "unsupported dest shorthand: ", dsh);
            break;
    }
}

void
xen_op_handler::xapic_handle_write_lvt_timer(uint64_t val)
{
    using namespace eapis::intel_x64::lapic;

    const auto mode = lvt::timer::mode::get(val);
    switch (mode) {
        case lvt::timer::mode::one_shot:
            break;
        case lvt::timer::mode::tsc_deadline:
            m_vcpu->set_timer_vector(lvt::timer::vector::get(val));
            ADD_VMX_PET_HANDLER(handle_vmx_pet);
            break;
        default:
            throw std::runtime_error("Unsupported LVT timer mode: " +
                                     std::to_string(mode));
    }

    m_vcpu->lapic_write(lvt::timer::indx, val);
}

uint8_t *
xen_op_handler::map_rip(xen_op_handler::rip_cache_t &rc, uint64_t rip, uint64_t len)
{
    auto itr = rc.find(rip);
    if (itr != rc.end()) {
        return itr->second.get();
    }

    auto ump = m_vcpu->map_gva_4k<uint8_t>(rip, len);
    if (!ump) {
        throw std::runtime_error("handle_xapic_write::map_gva_4k failed");
    }

    rc[rip] = std::move(ump);
    itr = rc.find(rip);

    return itr->second.get();
}

bool
xen_op_handler::xapic_handle_write(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::ept_violation_handler::info_t &info)
{
    using namespace eapis::intel_x64::lapic;

    if (bfn::upper(info.gpa) != m_vcpu->lapic_base()) {
        return false;
    }

    const auto idx = bfn::lower(info.gpa) >> 2;
    if (idx == eoi::indx) {
        info.ignore_advance = false;
        return true;
    }

    const auto rip = ::intel_x64::vmcs::guest_rip::get();
    const auto len = ::intel_x64::vmcs::vm_exit_instruction_length::get();
    const auto buf = this->map_rip(m_rc_xapic, rip, len);

    hyperkernel::intel_x64::insn_decoder dec(buf, len);
    const auto val = src_op_value(vcpu, dec.src_op());
    switch (idx) {
        case icr_low::indx:
            this->xapic_handle_write_icr(val);
            break;
        case lvt::timer::indx:
            this->xapic_handle_write_lvt_timer(val);
            break;
        case icr_high::indx:
        case id::indx:
        case tpr::indx:
        case ldr::indx:
        case dfr::indx:
        case svr::indx:
        case lvt::lint0::indx:
        case lvt::lint1::indx:
        case lvt::error::indx:
        case esr::indx:
        case initial_count::indx:
            m_vcpu->lapic_write(idx, val);
            break;
        case 0xd0:
            bfalert_info(0, "received perf interrupt");
            break;
        default:
            bfalert_nhex(0, "unhandled xapic write indx:", idx);
            return false;
    }

    info.ignore_advance = false;
    return true;
}

bool
xen_op_handler::ioapic_handle_write(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::ept_violation_handler::info_t &info)
{
    using namespace eapis::intel_x64::ioapic;

    if (bfn::upper(info.gpa) != m_vcpu->ioapic_base()) {
        return false;
    }

    const auto rip = ::intel_x64::vmcs::guest_rip::get();
    const auto len = ::intel_x64::vmcs::vm_exit_instruction_length::get();
    const auto buf = this->map_rip(m_rc_ioapic, rip, len);

    hyperkernel::intel_x64::insn_decoder dec(buf, len);
    const auto val = src_op_value(vcpu, dec.src_op());
    switch (info.gpa & 0xFF) {
        case sel_offset:
            m_vcpu->ioapic_select(val);
            m_vcpu->ioapic_set_window(m_vcpu->ioapic_read());
            break;
        case win_offset:
            m_vcpu->ioapic_write(val);
            m_vcpu->ioapic_set_window(val);

        default:
            throw std::invalid_argument("Invalid IOAPIC write: " +
                                        std::to_string(info.gpa));
    }

    bfdebug_nhex(0, "IOAPIC write: gpa:", info.gpa);
    info.ignore_advance = false;
    return true;
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
    using namespace ::intel_x64::msrs::ia32_misc_enable;

    // Pass through
    // - fast strings
    // - monitor FSM
    // - xd bit disable
    //
    // and disable everything else for now
    //
    auto_therm_control::disable(info.val);
    perf_monitor::disable(info.val);
    branch_trace_storage::disable(info.val);
    processor_sampling::disable(info.val);
    intel_speedstep::disable(info.val);
    limit_cpuid_maxval::disable(info.val);
    xtpr_message::disable(info.val);

    // Clear reserved bits
    //
    info.val &= ~0xFFFFFFFBFF3AE776U;

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
    m_apic_base = val;
    info.val = val;

    return true;
}

// We can't use x2apic with a linux domU unless we disable
// XENFEAT_hvm_pirqs and XENFEAT_hvm_callback_via
//
bool
xen_op_handler::ia32_apic_base_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    using namespace ::intel_x64::msrs::ia32_apic_base;
    bfignored(vcpu);

    switch (state::get(info.val)) {
        case state::xapic:
            break;
        default:
            bfalert_info(0, "Unhandled LAPIC state change");
            dump(0, info.val);
            return false;
    }

    m_apic_base = info.val;
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

bool
xen_op_handler::handle_tsc_deadline(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);
    m_pet_ticks = 0;

    const auto tick = ::x64::read_tsc::get();
    const auto next = info.val;

    if (next - tick > (1ULL << m_pet_shift)) {
        m_pet_ticks = (next - tick) >> m_pet_shift;
        m_vcpu->set_vmx_preemption_timer(m_pet_ticks);
        m_vcpu->enable_vmx_preemption_timer();
        return true;
    }

    // Here we have a deadline that is in the
    // past, so we queue the interrupt immediately

    m_vcpu->queue_timer_interrupt();
    return true;
}

// -----------------------------------------------------------------------------
// CPUID
// -----------------------------------------------------------------------------

bool
xen_op_handler::cpuid_ack_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfdebug_nhex(0, "ack received", vcpu->rax());
    return true;
}

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
xen_op_handler::cpuid_leaf4_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    using namespace ::intel_x64::cpuid::cache_parameters::eax;
    bfignored(vcpu);

    info.rax &= ~max_ids_logical::mask;
    info.rax &= ~max_ids_physical::mask;

    return true;
}


bool
xen_op_handler::cpuid_leaf1_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rcx &= ~::intel_x64::cpuid::feature_information::ecx::monitor::mask;
    info.rcx &= ~::intel_x64::cpuid::feature_information::ecx::vmx::mask;
    info.rcx &= ~::intel_x64::cpuid::feature_information::ecx::tm2::mask;
    info.rcx &= ~::intel_x64::cpuid::feature_information::ecx::sdbg::mask;
    info.rcx &= ~::intel_x64::cpuid::feature_information::ecx::xsave::mask;
    info.rcx &= ~::intel_x64::cpuid::feature_information::ecx::osxsave::mask;

    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::vme::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::de::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::mce::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::mtrr::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::mca::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::ds::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::acpi::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::tm::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::pbe::mask;

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
    // - TSC_ADJUST         need to properly emulate TSC offsetting
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
    // - TSC_AUX            need to properly emulate TSC offsetting
    // - SGX_LC             no plans to support

    if (info.rcx != 0) {
        info.rax = 0U;
        info.rbx = 0U;
        info.rcx = 0U;
        info.rdx = 0U;
    }

    info.rax = 1U;
    info.rbx &= 0x19C23D9U;
    info.rcx &= 0U;
    info.rdx = 0U;

    return true;
}

// This handler is only needed when we are running on vmware.
// It returns the TSC Hz directly in eax rather than the crystal
// Hz. Since (rbx / rax) = 1, the result returned from
// arch/x86/kernel/tsc.c:native_calibrate_tsc is correct. This
// is temporary until we find a better solution; if native_calibrate_tsc
// changes then this will probably break.
//
bool
xen_op_handler::cpuid_leaf15_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    if (vmware_guest()) {
        expects(m_tsc_freq_khz > 0);
        info.rax = 1U;
        info.rbx = 1U;
        info.rcx = m_tsc_freq_khz * 1000U;
        info.rdx = 0U;
    }

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
    // - TSC_AUX            need to properly emulate TSC offsetting

    info.rbx = 0U;
    info.rcx &= 0x121U;
    info.rdx &= 0x10100800U;

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
    info.rax |= XEN_HVM_CPUID_X2APIC_VIRT;
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

static bool own_pci_dev(::x64::pci::addr_t cf8)
{
    using namespace vtd_sandbox::hidden_nic;

    uint32_t addr = (cf8 | 0x80000000UL) & ~0xFFUL;
    ::x64::portio::outd(0xCF8, addr);

    return ::x64::portio::ind(0xCFC) == vendor_device;
}

static bool pci_config_in(
    ::x64::pci::addr_t cf8,
    ::x64::portio::port_addr_type port,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    using namespace ::x64::portio;
    namespace io = vmcs_n::exit_qualification::io_instruction;

    ::x64::portio::outd(0xCF8, cf8);

    switch (info.size_of_access) {
        case io::size_of_access::one_byte:  info.val = inb(port); break;
        case io::size_of_access::two_byte:  info.val = inw(port); break;
        case io::size_of_access::four_byte: info.val = ind(port); break;
        default: bfdebug_nhex(0,
            "invalid portio in size:", info.size_of_access);
            return false;
    }

    return true;
}

static bool pci_config_out(
    ::x64::pci::addr_t cf8,
    ::x64::portio::port_addr_type port,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    using namespace ::x64::portio;
    namespace io = vmcs_n::exit_qualification::io_instruction;

    ::x64::portio::outd(0xCF8, cf8);

    switch (info.size_of_access) {
        case io::size_of_access::one_byte:  outb(port, info.val); break;
        case io::size_of_access::two_byte:  outw(port, info.val); break;
        case io::size_of_access::four_byte: outd(port, info.val); break;
        default: bfdebug_nhex(0,
            "invalid portio in size:", info.size_of_access);
            return false;
    }

    return true;
}

bool
xen_op_handler::handle_cf8_out(
        gsl::not_null<vcpu_t *> vcpu,
        eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    m_cf8 = info.val;
    m_own_pci_dev = own_pci_dev(info.val);

    return true;
}

bool
xen_op_handler::handle_cf8_in(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_cf8;
    return true;
}

bool
xen_op_handler::handle_cfd_in(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (m_own_pci_dev) {
        return pci_config_in(m_cf8, 0xCFD, info);
    }

    return false;
}

bool
xen_op_handler::handle_cfb_in(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (m_own_pci_dev) {
        return pci_config_in(m_cf8, 0xCFB, info);
    }

    if (!::x64::pci::valid_bridge(m_cf8)) {
        return this->io_ones_handler(vcpu, info);
    }

    return pci_config_in(m_cf8, 0xCFB, info);
}

bool
xen_op_handler::handle_cfb_out(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (m_own_pci_dev) {
        return pci_config_out(m_cf8, 0xCFB, info);
    }

    if (!::x64::pci::valid_bridge(m_cf8)) {
        return this->io_ones_handler(vcpu, info);
    }

    return pci_config_out(m_cf8, 0xCFB, info);
}

bool
xen_op_handler::handle_cfc_out(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (m_own_pci_dev) {
        return pci_config_out(m_cf8, 0xCFC, info);
    }

    bferror_info(0, "CFC out for non-NIC");
    return false;
}

bool
xen_op_handler::handle_cfc_in(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    using namespace ::x64::portio;
    namespace io = vmcs_n::exit_qualification::io_instruction;

    if (m_own_pci_dev) {
        return pci_config_in(m_cf8, 0xCFC, info);
    }

    if (!::x64::pci::valid_bridge(m_cf8)) {
        return this->io_ones_handler(vcpu, info);
    }

    return pci_config_in(m_cf8, 0xCFC, info);
}

bool
xen_op_handler::handle_cfe_in(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    using namespace ::x64::portio;
    namespace io = vmcs_n::exit_qualification::io_instruction;

    if (m_own_pci_dev) {
        return pci_config_in(m_cf8, 0xCFE, info);
    }

    if (!::x64::pci::valid_bridge(m_cf8)) {
        return this->io_ones_handler(vcpu, info);
    }

    return pci_config_in(m_cf8, 0xCFE, info);
}

bool
xen_op_handler::handle_cfd_out(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (m_own_pci_dev) {
        return pci_config_out(m_cf8, 0xCFD, info);
    }

    bferror_info(0, "CFD out for non-NIC");
    return false;
}

bool
xen_op_handler::handle_cfe_out(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    if (m_own_pci_dev) {
        return pci_config_out(m_cf8, 0xCFE, info);
    }

    bferror_info(0, "CFE out for non-NIC");
    return false;
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
        case XENMEM_decrease_reservation:
            this->XENMEM_decrease_reservation_handler(vcpu);
            return true;

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
xen_op_handler::XENMEM_decrease_reservation_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<xen_memory_reservation_t>(vcpu->rsi());

        expects(arg->domid == DOMID_SELF);
        expects(arg->extent_order == 0);

        auto gva = arg->extent_start.p;
        auto len = arg->nr_extents * sizeof(xen_pfn_t);
        auto map = vcpu->map_gva_4k<xen_pfn_t>(gva, len);
        auto gfn = map.get();

        for (auto i = 0; i < arg->nr_extents; i++) {
            auto dom = m_vcpu->dom();
            auto gpa = (gfn[i] << x64::pt::page_shift);
            dom->unmap(gpa);
            dom->release(gpa);
        }

        vcpu->set_rax(arg->nr_extents);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })

}

bool
xen_op_handler::local_xenstore() const
{ return m_vcpu->id() == 0x10000; }

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
                if (vmware_guest()) {
                    m_shared_info->vcpu_info[0].time.pad0 = SIF_BFV_GUEST;
                }
                if (this->local_xenstore()) {
                    m_shared_info->vcpu_info[0].time.pad0 |= SIF_LOCAL_STORE;
                }
                break;

            case XENMAPSPACE_grant_table:
                m_gnttab_op->mapspace_grant_table(xen_add_to_physmap_arg.get());
                break;

            default:
                throw std::runtime_error(
                    "XENMEM_add_to_physmap: unknown space: " +
                    std::to_string(xen_add_to_physmap_arg->space));
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
//        info->submap |= (1 << XENFEAT_hvm_safe_pvclock);
        info->submap |= (1 << XENFEAT_hvm_pirqs);
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
// HYPERVISOR_grant_table_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_grant_table_op(gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_grant_table_op) {
        return false;
    }

    switch (vcpu->rdi()) {
        case GNTTABOP_query_size:
            this->GNTTABOP_query_size_handler(vcpu);
            return true;

        case GNTTABOP_set_version:
            this->GNTTABOP_set_version_handler(vcpu);
            return true;

        default:
            break;
    }

    throw std::runtime_error("unknown HYPERVISOR_grant_tab_op cmd");
}

void
xen_op_handler::GNTTABOP_query_size_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<gnttab_query_size_t>(vcpu->rsi());
        expects(arg->dom == DOMID_SELF);
        m_gnttab_op->query_size(arg.get());
        vcpu->set_rax(SUCCESS);
    } catchall ({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::GNTTABOP_set_version_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<gnttab_set_version_t>(vcpu->rsi());
        m_gnttab_op->set_version(arg.get());
        vcpu->set_rax(SUCCESS);
    } catchall ({
        vcpu->set_rax(FAILURE);
    })
}

// -----------------------------------------------------------------------------
// HYPERVISOR_vcpu_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_vcpu_op(gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_vcpu_op) {
        return false;
    }

    switch (vcpu->rdi()) {
        case VCPUOP_stop_periodic_timer:
            this->VCPUOP_stop_periodic_timer_handler(vcpu);
            return true;

        case VCPUOP_register_vcpu_info:
            this->VCPUOP_register_vcpu_info_handler(vcpu);
            return true;

        case VCPUOP_stop_singleshot_timer:
            this->VCPUOP_stop_singleshot_timer_handler(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_vcpu_op: " +
                             std::to_string(vcpu->rdi()));
}

void
xen_op_handler::VCPUOP_stop_periodic_timer_handler(gsl::not_null<vcpu *> vcpu)
{
    vcpu->set_rax(SUCCESS);
}

void
xen_op_handler::VCPUOP_stop_singleshot_timer_handler(gsl::not_null<vcpu *> vcpu)
{
    vcpu->set_rax(SUCCESS);
}

void
xen_op_handler::VCPUOP_register_vcpu_info_handler(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        expects(m_shared_info);
        expects(vcpu->rsi() == 0);

        auto arg = vcpu->map_arg<vcpu_register_vcpu_info_t>(vcpu->rdx());
        expects(arg->offset <= ::x64::pt::page_size - sizeof(vcpu_info_t));

        auto gpa = arg->mfn << ::x64::pt::page_shift;
        m_vcpu_info_ump = vcpu->map_gpa_4k<uint8_t>(gpa);

        uint8_t *base = m_vcpu_info_ump.get() + arg->offset;
        m_vcpu_info = reinterpret_cast<vcpu_info_t *>(base);

        vcpu->set_rax(SUCCESS);
    } catchall ({
        vcpu->set_rax(FAILURE);
    })
}

// -----------------------------------------------------------------------------
// HYPERVISOR_event_channel_op
// -----------------------------------------------------------------------------

bool
xen_op_handler::HYPERVISOR_event_channel_op(gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_event_channel_op) {
        return false;
    }

    switch (vcpu->rdi()) {
        case EVTCHNOP_init_control:
            this->EVTCHNOP_init_control_handler(vcpu);
            return true;

        case EVTCHNOP_expand_array:
            this->EVTCHNOP_expand_array_handler(vcpu);
            return true;

        case EVTCHNOP_alloc_unbound:
            this->EVTCHNOP_alloc_unbound_handler(vcpu);
            return true;

        case EVTCHNOP_bind_ipi:
            this->EVTCHNOP_bind_ipi_handler(vcpu);
            return true;

        case EVTCHNOP_bind_virq:
            this->EVTCHNOP_bind_virq_handler(vcpu);
            return true;

        case EVTCHNOP_bind_vcpu:
            this->EVTCHNOP_bind_vcpu_handler(vcpu);
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
xen_op_handler::EVTCHNOP_bind_ipi_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<evtchn_bind_ipi_t>(vcpu->rsi());
        m_evtchn_op->bind_ipi(arg.get());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::EVTCHNOP_bind_virq_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<evtchn_bind_virq_t>(vcpu->rsi());
        m_evtchn_op->bind_virq(arg.get());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::EVTCHNOP_bind_vcpu_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<evtchn_bind_vcpu_t>(vcpu->rsi());
        m_evtchn_op->bind_vcpu(arg.get());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
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
xen_op_handler::EVTCHNOP_expand_array_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<evtchn_expand_array_t>(vcpu->rsi());
        m_evtchn_op->expand_array(arg.get());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::EVTCHNOP_alloc_unbound_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<evtchn_alloc_unbound_t>(vcpu->rsi());
        m_evtchn_op->alloc_unbound(arg.get());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
xen_op_handler::EVTCHNOP_send_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<evtchn_send_t>(vcpu->rsi());
        m_evtchn_op->send(arg.get());
        vcpu->set_rax(SUCCESS);

        static int count = 0;
        if (!count) {
            auto ptr = m_console.get();
            for (auto i = 0; i < 64; i++) {
                printf("%02x", ptr[i]);
            }
            printf("\n");
            count++;
        }

        if (count == 1) {
            auto ptr = m_console.get();
            for (auto i = 0; i < 64; i++) {
                printf("%02x", ptr[i]);
            }
            printf("\n");
            count++;
        }
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

    const auto vector = via & 0xFFU;
    if (vector < 0x20U || vector > 0xFFU) {
        throw std::invalid_argument(
            "invalid callback vector: " + std::to_string(vector)
        );
    }
}

void
xen_op_handler::HVMOP_set_param_handler(gsl::not_null<vcpu *> vcpu)
{
    try {
        auto arg = vcpu->map_arg<xen_hvm_param_t>(vcpu->rsi());

        switch (arg->index) {
            case HVM_PARAM_CALLBACK_IRQ:
                verify_callback_via(arg->value);
                m_evtchn_op->set_callback_via(arg->value & 0xFFU);
                vcpu->set_rax(SUCCESS);
                break;

            default:
                bfalert_info(0, "Unsupported HVM set_param:");
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
        auto arg = vcpu->map_arg<xen_hvm_param_t>(vcpu->rsi());

        switch (arg->index) {
            case HVM_PARAM_CONSOLE_EVTCHN:
                arg->value = m_evtchn_op->bind_console();
                vcpu->set_rax(FAILURE);
                break;

            case HVM_PARAM_CONSOLE_PFN:
                m_console = vcpu->map_gpa_4k<uint8_t>(CONSOLE_GPA);
                arg->value = CONSOLE_GPA >> x64::pt::page_shift;
                break;

//            case HVM_PARAM_STORE_EVTCHN:
//                arg->value = m_evtchn_op->bind_store();
//                break;

            default:
                bfdebug_info(0, "Unsupported HVM get_param:");
                bfdebug_subnhex(0, "domid", arg->domid);
                bfdebug_subnhex(0, "index", arg->index);
                vcpu->set_rax(FAILURE);
                return;
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
