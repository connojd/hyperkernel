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

#ifndef XEN_OP_INTEL_X64_HYPERKERNEL_H
#define XEN_OP_INTEL_X64_HYPERKERNEL_H

#define __XEN_INTERFACE_VERSION__ 0x040900

#include "../base.h"

#include "public/xen.h"
#include "public/vcpu.h"
#include "public/grant_table.h"
#include "public/arch-x86/cpuid.h"

#include "evtchn_op.h"
#include "gnttab_op.h"
#include "sched_op.h"

#include <eapis/hve/arch/intel_x64/vmexit/cpuid.h>
#include <eapis/hve/arch/intel_x64/vmexit/wrmsr.h>
#include <eapis/hve/arch/intel_x64/vmexit/rdmsr.h>
#include <eapis/hve/arch/intel_x64/vmexit/io_instruction.h>
#include <eapis/hve/arch/intel_x64/vmexit/ept_violation.h>

#include <eapis/hve/arch/x64/unmapper.h>

#include <bfcallonce.h>


// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HYPERKERNEL_HVE
#ifdef SHARED_HYPERKERNEL_HVE
#define EXPORT_HYPERKERNEL_HVE EXPORT_SYM
#else
#define EXPORT_HYPERKERNEL_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HYPERKERNEL_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class vcpu;

class EXPORT_HYPERKERNEL_HVE xen_op_handler
{
public:

    xen_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~xen_op_handler() = default;

    shared_info_t *shared_info();

private:

    void run_delegate(bfobject *obj);
    bool exit_handler(gsl::not_null<vcpu_t *> vcpu);
    bool handle_hlt(gsl::not_null<vcpu_t *> vcpu);

    // -------------------------------------------------------------------------
    // MSRS
    // -------------------------------------------------------------------------

    void isolate_msr(uint32_t msr);

    bool rdmsr_zero_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info);
    bool wrmsr_ignore_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool rdmsr_pass_through_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info);
    bool wrmsr_pass_through_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool wrmsr_store_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool ia32_misc_enable_rdmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info);
    bool ia32_misc_enable_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool ia32_apic_base_rdmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info);
    bool ia32_apic_base_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool xen_hypercall_page_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);
    bool xen_debug_ndec_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);
    bool xen_debug_nhex_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    bool handle_tsc_deadline(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

    // -------------------------------------------------------------------------
    // CPUID
    // -------------------------------------------------------------------------

    bool cpuid_ack_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_zero_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_pass_through_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);

    bool cpuid_leaf1_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf4_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf6_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf7_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool cpuid_leaf80000001_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf1_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf2_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf3_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf5_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);

    // -------------------------------------------------------------------------
    // IO Instructions
    // -------------------------------------------------------------------------

    bool io_zero_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool io_ones_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool io_ignore_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);

    // -------------------------------------------------------------------------
    // VMCalls
    // -------------------------------------------------------------------------

    bool HYPERVISOR_memory_op(gsl::not_null<vcpu *> vcpu);
    void XENMEM_decrease_reservation_handler(gsl::not_null<vcpu *> vcpu);
    void XENMEM_add_to_physmap_handler(gsl::not_null<vcpu *> vcpu);
    void XENMEM_memory_map_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_xen_version(gsl::not_null<vcpu *> vcpu);
    void XENVER_get_features_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_grant_table_op(gsl::not_null<vcpu *> vcpu);
    void GNTTABOP_query_size_handler(gsl::not_null<vcpu *> vcpu);
    void GNTTABOP_set_version_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_vm_assist(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_vcpu_op(gsl::not_null<vcpu *> vcpu);
    void VCPUOP_register_vcpu_info_handler(gsl::not_null<vcpu *> vcpu);
    void VCPUOP_stop_periodic_timer_handler(gsl::not_null<vcpu *> vcpu);
    void VCPUOP_stop_singleshot_timer_handler(gsl::not_null<vcpu *> vcpu);
    void VCPUOP_set_singleshot_timer_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_hvm_op(gsl::not_null<vcpu *> vcpu);
    void HVMOP_set_param_handler(gsl::not_null<vcpu *> vcpu);
    void HVMOP_get_param_handler(gsl::not_null<vcpu *> vcpu);
    void HVMOP_pagetable_dying_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_event_channel_op(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_init_control_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_expand_array_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_alloc_unbound_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_send_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_bind_ipi_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_bind_virq_handler(gsl::not_null<vcpu *> vcpu);
    void EVTCHNOP_bind_vcpu_handler(gsl::not_null<vcpu *> vcpu);

    bool HYPERVISOR_sched_op(gsl::not_null<vcpu *> vcpu);
    void SCHEDOP_yield_handler(gsl::not_null<vcpu *> vcpu);

    // -------------------------------------------------------------------------
    // Local APIC
    // -------------------------------------------------------------------------

    bool xapic_handle_write(
        gsl::not_null<vcpu_t *> vcpu,
        eapis::intel_x64::ept_violation_handler::info_t &info);

    void xapic_handle_write_icr(uint64_t icr_low);
    void xapic_handle_write_lvt_timer(uint64_t timer);
    void xapic_handle_write_init_count(uint64_t val);

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    bool local_xenstore() const;
    uint64_t tsc_to_sys_time() const;
    uint64_t tsc_to_sys_time(uint64_t tsc) const;
    void reset_vcpu_time_info();
    void update_vcpu_time_info();

    bool handle_vmx_pet(gsl::not_null<vcpu_t *> vcpu);

    // -------------------------------------------------------------------------
    // Quirks
    // -------------------------------------------------------------------------

    void register_unplug_quirk();

private:

#ifndef MIN_TSC_TICKS
#define MIN_TSC_TICKS 20000
#endif

#ifndef MIN_EXIT_TICKS
#define MIN_EXIT_TICKS 16000
#endif

    static constexpr auto min_tsc_ticks = MIN_TSC_TICKS;
    static constexpr auto min_exit_ticks = MIN_EXIT_TICKS;

    bfn::once_flag m_tsc_once_flag{};

    uint64_t m_apic_base{};

    uint64_t m_tsc_freq_khz{};
    uint64_t m_tsc_vector{};
    uint64_t m_tsc_exit{0};
    uint64_t m_tsc_lost{0};

    uint64_t m_pet_shift{};
    uint64_t m_pet_ticks{};

    std::unordered_map<uint32_t, uint64_t> m_msrs;
    std::unordered_map<uint64_t, eapis::x64::unique_map<uint8_t>> m_xapic_rip_cache;

private:

    vcpu *m_vcpu;
    vcpu_info_t *m_vcpu_info;

    uint64_t m_hypercall_page_gpa{};

    eapis::x64::unique_map<vcpu_runstate_info_t> m_runstate_info;
    eapis::x64::unique_map<vcpu_time_info_t> m_time_info;
    eapis::x64::unique_map<shared_info_t> m_shared_info;
    eapis::x64::unique_map<uint8_t> m_vcpu_info_ump;
    eapis::x64::unique_map<uint8_t> m_console;
    eapis::x64::unique_map<uint8_t> m_store;

    std::unique_ptr<hyperkernel::intel_x64::evtchn_op> m_evtchn_op;
    std::unique_ptr<hyperkernel::intel_x64::gnttab_op> m_gnttab_op;
    std::unique_ptr<hyperkernel::intel_x64::sched_op> m_sched_op;

public:

    /// @cond
    xen_op_handler(xen_op_handler &&) = default;
    xen_op_handler &operator=(xen_op_handler &&) = default;

    xen_op_handler(const xen_op_handler &) = delete;
    xen_op_handler &operator=(const xen_op_handler &) = delete;

    /// @endcond
};

}

#endif
