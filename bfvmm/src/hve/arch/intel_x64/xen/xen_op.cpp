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

#include <bfcallonce.h>
#include <bfgpalayout.h>

#include <list>
#include <iostream>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/lapic.h>
#include <hve/arch/intel_x64/pci.h>
#include <hve/arch/intel_x64/iommu.h>
#include <eapis/hve/arch/intel_x64/time.h>
#include <eapis/hve/arch/intel_x64/vtd/iommu.h>

#include <xen/public/xen.h>
#include <xen/public/event_channel.h>
#include <xen/public/memory.h>
#include <xen/public/version.h>
#include <xen/public/vcpu.h>
#include <xen/public/hvm/hvm_op.h>
#include <xen/public/hvm/params.h>
#include <xen/public/arch-x86/cpuid.h>

#include <hve/arch/intel_x64/xen/xen_op.h>
#include <hve/arch/intel_x64/xen/evtchn_op.h>

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
    gsl::not_null<vcpu *> vcpu, gsl::not_null<domain *> domain
) :
    m_vcpu{vcpu},
    m_domain{domain},
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
        ADD_WRMSR_HANDLER(::intel_x64::msrs::ia32_apic_base::addr, dom0_apic_base);
        return;
    }

    domain->setup_vcpu_uarts(vcpu);

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

    EMULATE_RDMSR(0x0FE, rdmsr_mtrr_cap);
    EMULATE_RDMSR(0x2FF, rdmsr_mtrr_def);
    EMULATE_WRMSR(0x2FF, wrmsr_mtrr_def);

    // TODO: the number of ranges == number of e820 entries
    EMULATE_RDMSR(0x200, rdmsr_mtrr_physbase);
    EMULATE_RDMSR(0x201, rdmsr_mtrr_physmask);

    EMULATE_RDMSR(0x202, rdmsr_mtrr_physbase);
    EMULATE_RDMSR(0x203, rdmsr_mtrr_physmask);

    EMULATE_RDMSR(0x204, rdmsr_mtrr_physbase);
    EMULATE_RDMSR(0x205, rdmsr_mtrr_physmask);

    EMULATE_RDMSR(0x206, rdmsr_mtrr_physbase);
    EMULATE_RDMSR(0x207, rdmsr_mtrr_physmask);

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

    /// ACPI SCI interrupt trigger mode
    EMULATE_IO_INSTRUCTION(0x4D0, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0x4D1, io_zero_handler, io_ignore_handler);

    /// NMI assertion
    EMULATE_IO_INSTRUCTION(0x70, io_zero_handler, io_ignore_handler);
    EMULATE_IO_INSTRUCTION(0x71, io_zero_handler, io_ignore_handler);

    /// Ports used for TSC calibration against the PIT. See
    /// arch/x86/kernel/tsc.c:pit_calibrate_tsc for detail.
    /// Note that these ports are accessed on the Intel NUC.
    ///
    vcpu->pass_through_io_accesses(0x42);
    vcpu->pass_through_io_accesses(0x43);
    vcpu->pass_through_io_accesses(0x61);

    this->register_unplug_quirk();

    ADD_EPT_WRITE_HANDLER(xapic_handle_write);

    m_pet_shift = ::intel_x64::msrs::ia32_vmx_misc::preemption_timer_decrement::get();
    m_tsc_freq_khz = tsc_frequency();

    m_vcpu->add_handler(
        exit_reason::basic_exit_reason::hlt,
        ::handler_delegate_t::create<xen_op_handler, &xen_op_handler::handle_hlt>(this)
    );

    if (vcpu->dom()->is_ndvm()) {
        EMULATE_IO_INSTRUCTION(0xCF8, io_cf8_in, io_cf8_out);
        EMULATE_IO_INSTRUCTION(0xCFB, io_cfb_in, io_cfb_out);
        EMULATE_IO_INSTRUCTION(0xCFC, io_cfc_in, io_cfc_out);
        EMULATE_IO_INSTRUCTION(0xCFD, io_cfd_in, io_cfd_out);
        EMULATE_IO_INSTRUCTION(0xCFE, io_cfe_in, io_cfe_out);

        m_nic = bdf_to_cf8(vcpu->dom()->ndvm_bus(), 0, 0); // assumes NIC is only one on bus
        m_phys_vec = g_visr->get_phys_vector(m_vcpu->id());
        bfdebug_nhex(0, "NDVM acquired vector:", m_phys_vec);
        bfdebug_nhex(0, "NDVM acquired cf8:", m_nic);
        bfdebug_nhex(0, "NDVM acquired bus:", cf8_to_bus(m_nic));
        bfdebug_nhex(0, "NDVM acquired dev:", cf8_to_dev(m_nic));
        bfdebug_nhex(0, "NDVM acquired fun:", cf8_to_fun(m_nic));

        this->pci_init_caps();
        this->pci_init_bars();
        this->pci_init_nic();
    } else {
        EMULATE_IO_INSTRUCTION(0xCF8, io_ones_handler, io_ignore_handler);
        EMULATE_IO_INSTRUCTION(0xCFA, io_ones_handler, io_ignore_handler);
        EMULATE_IO_INSTRUCTION(0xCFB, io_ones_handler, io_ignore_handler);
        EMULATE_IO_INSTRUCTION(0xCFC, io_ones_handler, io_ignore_handler);
        EMULATE_IO_INSTRUCTION(0xCFD, io_ones_handler, io_ignore_handler);
        EMULATE_IO_INSTRUCTION(0xCFE, io_ones_handler, io_ignore_handler);
        EMULATE_IO_INSTRUCTION(0xCFF, io_ones_handler, io_ignore_handler);
    }
}

// Do fixups after Windows to ensure we start from a known initial state
//
void
xen_op_handler::pci_init_nic()
{
    // status_command - disable INTx
    cf8_write_reg(m_nic, 0x1, 0x00100407);

    // Disable MSI
    cf8_write_reg(m_nic, 0x14, 0x00807005);

    // Bus-level reset of the NIC's bus
    //auto bridge = bdf_to_cf8(0, 0x1C, 0);
    //auto ctl = cf8_read_reg(bridge, 0xF);
    //auto tmp = ctl | (0x40UL << 16);

    //cf8_write_reg(bridge, 0xF, tmp);
    //cf8_write_reg(bridge, 0xF, ctl);
}


void
xen_op_handler::pci_init_caps()
{
    if ((cf8_read_reg(m_nic, 0x1) & 0x0010'0000) == 0) {
        printf("NIC: capability list empty\n");
        return;
    }

    const auto ptr = cf8_read_reg(m_nic, 0xD) & 0xFF;
    auto reg = ptr >> 2U;
    auto prev = 0xD;

//    printf("NIC: Capability pointer: %x\n", reg);

    while (reg != 0) {
        constexpr auto id_msi = 0x05;
        constexpr auto id_msix = 0x11;

        const auto cap = cf8_read_reg(m_nic, reg);
        const auto id = cap & 0xFF;

        if (id == id_msi) {
            m_msi_cap = reg;
            prev = reg;
            reg = (cap & 0xFF00) >> (8 + 2);
            continue;
        }

        if (id != id_msix) {
            prev = reg;
            reg = (cap & 0xFF00) >> (8 + 2);
            continue;
        }

        // We don't update prev here like in the other cases because
        // the only reason prev is around is to set m_msix_cap_prev
        //
        m_msix_cap = reg;
        m_msix_cap_prev = prev;
        m_msix_cap_next = reg = (cap & 0xFF00) >> (8 + 2);
    }

    ensures(m_msi_cap != 0);

//    printf("NIC: Capability found: MSI at byte 0x%x, reg 0x%x\n",
//           m_msi_cap << 2,
//           m_msi_cap);

    if (m_msix_cap != 0) {
//        printf("NIC: Capability found: MSI-x at byte 0x%x, reg 0x%x\n",
//               m_msix_cap << 2,
//               m_msix_cap);
    }
}

void
xen_op_handler::pci_init_bars()
{
    for (auto reg = 0x4; reg <= 0x9; reg++) {
        m_nic_bar.at(reg - 0x4) = cf8_read_reg(m_nic, reg);
    }

    parse_bars_normal(m_nic, m_nic_bar_list);

    for (const auto &bar : m_nic_bar_list) {
        if (bar.bar_type == pci_bar_io) {
//            bfdebug_info(0, "NIC: io bar:");
//            bfdebug_subnhex(0, "addr", bar.addr);
//            bfdebug_subnhex(0, "size", bar.size);

            for (auto p = 0; p < bar.size; p++) {
                m_vcpu->pass_through_io_accesses(bar.addr + p);
            }

            continue;
        }

//        bfdebug_info(0, "NIC: mm bar:");
//        bfdebug_subnhex(0, "addr", bar.addr);
//        bfdebug_subnhex(0, "size", bar.size);
//        bfdebug_subbool(0, "64-bit", bar.mm_type == 2);
//        bfdebug_subbool(0, "prefetchable", bar.prefetchable);

        for (auto i = 0; i < bar.size; i += ::x64::pt::page_size) {
            m_domain->map_4k_rw_uc(bar.addr + i, bar.addr + i);
        }
    }

//    cf8 = bdf_to_cf8(0, 0x1C, 0);
//    m_bridge_bar[0] = cf8_read_reg(cf8, 0x4);
//    m_bridge_bar[1] = cf8_read_reg(cf8, 0x5);
//
//    // Map in NIC's PCIe mmconfig page
//    uintptr_t page = 0xf8000000 | (2 << 20);
//    m_domain->map_4k_rw_uc(page, page);
}

bool
xen_op_handler::io_cf8_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    info.val = m_cf8;
    return true;
}

bool
xen_op_handler::io_cf8_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    m_cf8 = info.val;
    return true;
}

bool
xen_op_handler::pci_msix_cap_prev_in(io_instruction_handler::info_t &info)
{
    expects(m_msix_cap != 0);
    expects(m_msix_cap_prev != 0);
    expects(m_msix_cap_prev == cf8_to_reg(m_cf8));

    const auto base = 0xD;
    const auto size = info.size_of_access;
    const auto port = info.port_number;
    const auto curr = m_msix_cap_prev;
    const auto next = m_msix_cap_next;

    if (curr == base) {
        info.val = (port == 0xCFC) ? next << 2 : 0;
        return true;
    }

    pci_info_in(m_cf8, info);

    switch (port) {
    case 0xCFC:
        if (size == io::size_of_access::one_byte) {
            break;
        }
        info.val &= 0xFFFF00FF;
        info.val |= next << (8 + 2);
        break;
    case 0xCFD:
        info.val &= 0xFFFFFF00;
        info.val |= next << 2;
        break;
    default:
        break;
    }

    return true;
}

bool
xen_op_handler::pci_owned_in(io_instruction_handler::info_t &info)
{
    expects(m_msix_cap_prev != 0);
    if (cf8_to_reg(m_cf8) == m_msix_cap_prev) {
        return this->pci_msix_cap_prev_in(info);
    }

    if (cf8_to_reg(m_cf8) == m_msix_cap) {
        bfalert_info(0, "Guest read from MSI-X capability register");
    }

    pci_info_in(m_cf8, info);

    switch (cf8_to_reg(m_cf8)) {
    case 0x1:
        if (info.port_number == 0xCFC) {
            info.val |= 0x400UL;
            pci_info_out(m_cf8, info);
            info.val |= 0x10UL;
        }
        break;
    case 0x3:
        if (info.port_number == 0xCFC) {
            info.val &= 0xFFFFFF00UL;
            info.val |= 0x10UL;
        }
        break;
//    case 0xD:
//        if (info.port_number == 0xCFC) {
//            info.val = 0x50;
//        }
//        break;
//    case 0x14: // MSI cap reg
//        if (info.port_number == 0xCFC) {
//            if (info.size_of_access > io::size_of_access::one_byte) {
//                info.val &= 0xFFFF00FFUL;
//            }
//        } else if (info.port_number == 0xCFD) {
//            expects(info.size_of_access == io::size_of_access::one_byte);
//            info.val = 0;
//        }
//        break;
    default:
        break;
    }

    return true;
}

bool
xen_op_handler::pci_host_bridge_in(io_instruction_handler::info_t &info)
{
    switch (cf8_to_reg(m_cf8)) {
        case 0x00:
        case 0x02:
        case 0x03:
        case 0x0B:
        case 0x0D:
        case 0x0F:
            pci_info_in(m_cf8, info);
            break;

        case 0x01:
            pci_info_in(m_cf8, info);
            switch (info.size_of_access) {
            case io::size_of_access::four_byte:
                info.val |= 0x00000400; // Disable pin interrupt
                info.val &= 0xFFEFFFFF; // Disable capability list
                break;
            case io::size_of_access::two_byte:
                if (info.port_number == 0xCFC) {
                    info.val |= 0x0400; // Disable pin interrupt
                } else if (info.port_number == 0xCFE) {
                    info.val &= 0xFFEF; // Disable capability list
                }
                break;
            case io::size_of_access::one_byte:
                if (info.port_number == 0xCFD) {
                    info.val |= 0x04;   // Disable pin interrupt
                } else if (info.port_number == 0xCFE) {
                    info.val &= 0xEF;   // Disable capability list
                }
                break;
            }
            break;

        default:
            info.val = 0;
            break;
    }

    return true;
}


// Normal -> not a PCI bridge -> config layout 0
//
bool
xen_op_handler::pci_hdr_normal_in(io_instruction_handler::info_t &info)
{
    if (this->owns_current_bdf()) {
//        printf("(owned)  ");
        return this->pci_owned_in(info);
    }

    if (is_host_bridge(m_cf8)) {
//        printf("(hostbr) ");
        return this->pci_host_bridge_in(info);
    }

    info.val = 0xFFFFFFFFUL;
    return true;
}

// PCI bridge -> config layout 1
//
bool
xen_op_handler::pci_hdr_pci_bridge_in(io_instruction_handler::info_t &info)
{
//    printf("(bridge) ");

//    if (cf8_to_dev(m_cf8) == 0x1c && cf8_to_fun(m_cf8) == 0) {
//            pci_info_in(m_cf8, info);
//            auto reg = cf8_to_reg(m_cf8);
//
//            switch (reg) {
//            case 0x01:
//                info.val |= 0x400UL;       // disable INTx
//                info.val &= ~0x00100000UL; // disable cap list
//                break;
//            default:
//                break;
//            }
//            return true;
//    }

    switch (cf8_to_reg(m_cf8)) {
        //case 0x00: // passthrough device/vendor register
        //case 0x02: // passthrough class register
        //case 0x03: // passthrough header type register
        //case 0x06: // passthrough secondary bus register
        ////case 0x0F: // passthrough secondary cmd register
        //    pci_info_in(m_cf8, info);
        //    break;

        //case 0x01:
        //    pci_info_in(m_cf8, info);
        //    switch (info.size_of_access) {
        //    case io::size_of_access::four_byte:
        //        info.val |= 0x00000400; // Disable pin interrupt
        //        info.val &= 0xFFEFFFFF; // Disable capability list
        //        break;
        //    case io::size_of_access::two_byte:
        //        if (info.port_number == 0xCFC) {
        //            info.val |= 0x0400; // Disable pin interrupt
        //        } else if (info.port_number == 0xCFE) {
        //            info.val &= 0xFFEF; // Disable capability list
        //        }
        //        break;
        //    case io::size_of_access::one_byte:
        //        if (info.port_number == 0xCFD) {
        //            info.val |= 0x04;   // Disable pin interrupt
        //        } else if (info.port_number == 0xCFE) {
        //            info.val &= 0xEF;   // Disable capability list
        //        }
        //        break;
        //    }
        //    break;

        //case 0x07:
        //    pci_info_in(m_cf8, info);
        //    switch (info.size_of_access) {
        //    case io::size_of_access::four_byte:
        //        info.val &= 0xFFFF0000; // Passthrough secondary status
        //        break;
        //    case io::size_of_access::two_byte:
        //        if (info.port_number == 0xCFC) {
        //            info.val = 0;       // Mask IO limit and base
        //        }
        //        break;
        //    case io::size_of_access::one_byte:
        //        if (info.port_number == 0xCFC || info.port_number == 0xCFD) {
        //            info.val = 0;       // Mask IO limit and base
        //        }
        //        break;
        //    }
        //    break;

        default:
//            info.val = 0;
            info.val = 0xFFFFFFFF;
            break;
    }

    return true;
}

bool
xen_op_handler::pci_in(io_instruction_handler::info_t &info)
{
    bool ret = false;

    switch (pci_header_type(m_cf8)) {
        case pci_hdr_normal:
        case pci_hdr_normal_multi:
            ret = this->pci_hdr_normal_in(info);
//            printf("data: %08lx\n", info.val);
            break;

        case pci_hdr_pci_bridge:
        case pci_hdr_pci_bridge_multi:
            ret = this->pci_hdr_pci_bridge_in(info);
//            printf("data: %08lx\n", info.val);
            break;

        case pci_hdr_nonexistant:
            info.val = 0xFFFFFFFFUL;
            //printf("(nexist) ");
            ret = true;
            break;

        default:
            bferror_nhex(0, "Unhandled PCI header:", pci_header_type(m_cf8));
            bferror_nhex(0, "m_cf8:", m_cf8);
            bferror_dump_cf8(0, m_cf8);
            bferror_lnbr(0); {
                const auto cf8 = ind(0xCF8);
                bferror_nhex(0, "0xCF8:", cf8);
                bferror_dump_cf8(0, cf8);
                bferror_lnbr(0);
            }
            bferror_nhex(0, "0xCFC:", ind(0xCFC));
            throw std::runtime_error("Unhandled PCI header");
    }

    //printf("data: %08lx\n", info.val);
    return ret;
}

bool
xen_op_handler::io_cfc_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    expects(info.port_number == 0xCFC);

    //debug_pci_in(m_cf8, info);
    return this->pci_in(info);
}

bool
xen_op_handler::io_cfd_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    expects(info.port_number == 0xCFD);

    //debug_pci_in(m_cf8, info);
    return this->pci_in(info);
}

bool
xen_op_handler::io_cfe_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    expects(info.port_number == 0xCFE);

    //debug_pci_in(m_cf8, info);
    return this->pci_in(info);
}

bool
xen_op_handler::pci_hdr_pci_bridge_out(io_instruction_handler::info_t &info)
{
//    printf("(bridge) ");

    if (cf8_to_dev(m_cf8) == 0x1c && (cf8_to_fun(m_cf8) == 0 || cf8_to_fun(m_cf8) == 7)) {
        if (cf8_to_reg(m_cf8) == 4 || cf8_to_reg(m_cf8) == 5) {
            if (info.val == 0xFFFFFFFF) {
                pci_info_out(m_cf8, info);
                return true;
            }

            if (info.val != m_bridge_bar.at(cf8_to_reg(m_cf8) - 4)) {
                bferror_info(0, "Attempt to remap PCI bridge bars");
                return false;
            }

            pci_info_out(m_cf8, info);
            return true;
        }
    }

    //bferror_dump_cf8(0, m_cf8);
    return this->io_ignore_handler(m_vcpu, info);
}

bool
xen_op_handler::pci_hdr_normal_out(io_instruction_handler::info_t &info)
{
    if (this->owns_current_bdf()) {
//        printf("(owned)  ");
        return this->pci_owned_out(info);
    }

    if (is_host_bridge(m_cf8)) {
//        printf("(hostbr) ");
        return this->io_ignore_handler(m_vcpu, info);
    }

    return false;
}

bool
xen_op_handler::pci_owned_msi_out(io_instruction_handler::info_t &info)
{
    const auto pci_reg = cf8_to_reg(m_cf8);
    pci_bars_t virt_bars;

    // Pass this one through so it can be enabled/disabled
    if (pci_reg == m_msi_cap) {
//        bfdebug_nhex(0, "MSI+0", info.val);
        pci_info_out(m_cf8, info);
        return true;
    }

    if (pci_reg == m_msi_cap + 1) {
        using namespace ::intel_x64::msrs;

        // Parse the APIC ID from VCPU's PoV
        auto msr = ia32_apic_base::get();
        auto hpa = ia32_apic_base::apic_base::get(msr);
        auto ptr = m_vcpu->map_hpa_4k<uint8_t>(hpa);
        auto apic_reg = *reinterpret_cast<uint32_t *>(ptr.get() + 0x20);
        auto phys_id = apic_reg >> 24;

        // Parse the APIC ID from NIC's PoV
        auto msi_addr = cf8_read_reg(m_cf8, pci_reg);
        auto nic_id = (msi_addr & 0xFF000) >> 12;

        //bfdebug_nhex(0, "visr_id", vtd::ndvm_apic_id);
//        bfdebug_nhex(0, "phys_id", phys_id);
//        bfdebug_nhex(0, "nic_id", nic_id);

        expects((info.val & 0x8) == 0); // For now we don't support redirection hints
        expects(ia32_apic_base::state::get(msr) == ia32_apic_base::state::xapic);
//        expects(phys_id == vtd::ndvm_apic_id);

        // Trust no one, clear reserved bits
        info.val &= ~0x00000FF0UL;

        // Program the proper physical apic id
        info.val &= ~0x000FF000UL;
        info.val |= (phys_id << 12);

        pci_info_out(m_cf8, info);
        return true;
    }

    if (pci_reg == m_msi_cap + 2) {
        if (info.val) {
            throw std::runtime_error("Non-zero write to upper MSI address:");
        }
    }

    if (pci_reg == m_msi_cap + 3) {
        // Save the vector linux expects
        //
        bfdebug_info(0, "xen_op: setting virt vector");
        bfdebug_subnhex(0, "vector", info.val & 0xFF);
        bfdebug_subnhex(0, "vcpuid", m_vcpu->id());
        g_visr->set_virt_vector(m_vcpu->id(), info.val & 0xFF);

        // We set the vector to the one visr expects and clear all
        // other bits. This implies the interrupt will be delivered
        // with fixed delivery mode, edge triggered. We can't trust
        // the host or guest to program this to our needs (Windows programmed
        // lowest-priority!).
        //
        info.val = m_phys_vec;
        pci_info_out(m_cf8, info);

//        bfdebug_nhex(0, "NIC MSI+0 hw:", cf8_read_reg(m_cf8, pci_reg - 3));
//        bfdebug_nhex(0, "NIC MSI+1 hw:", cf8_read_reg(m_cf8, pci_reg - 2));
//        bfdebug_nhex(0, "NIC MSI+2 hw:", cf8_read_reg(m_cf8, pci_reg - 1));
//        bfdebug_nhex(0, "NIC MSI+3 hw:", cf8_read_reg(m_cf8, pci_reg - 0));

        return true;
    }

    if (pci_reg == m_msi_cap + 4 && info.val) {
        throw std::runtime_error("Non-zero write to MSI+4");
    }
    if (pci_reg == m_msi_cap + 5 && info.val) {
        throw std::runtime_error("Non-zero write to MSI+5");
    }

    return true;
}

bool
xen_op_handler::pci_owned_out(io_instruction_handler::info_t &info)
{
    const auto reg = cf8_to_reg(m_cf8);
    expects(reg != m_msix_cap);

    if (reg >= 0x4 && reg <= 0x9) {
        if (info.val == 0xFFFFFFFF) {
            pci_info_out(m_cf8, info);
            return true;
        }

        if (info.val != m_nic_bar.at(cf8_to_reg(m_cf8) - 4)) {
            bferror_info(0, "Attempt to remap NIC bars");
            bferror_subnhex(0, "new", info.val);
            bferror_subnhex(0, "old", m_nic_bar.at(cf8_to_reg(m_cf8) - 4));
            bferror_subnhex(0, "reg", cf8_to_reg(m_cf8) - 4);
            //return true;
        }

        pci_info_out(m_cf8, info);
        return true;
    }

    if (reg < m_msi_cap || reg > m_msi_cap + 5) {
        pci_info_out(m_cf8, info);
        return true;
    }

    return this->pci_owned_msi_out(info);
}

bool
xen_op_handler::pci_host_bridge_out(io_instruction_handler::info_t &info)
{
    return false;
}

bool
xen_op_handler::pci_out(io_instruction_handler::info_t &info)
{
    bool ret = false;

    switch (pci_header_type(m_cf8)) {
        case pci_hdr_normal:
        case pci_hdr_normal_multi:
            ret = this->pci_hdr_normal_out(info);
            break;

        case pci_hdr_pci_bridge:
        case pci_hdr_pci_bridge_multi:
            ret = this->pci_hdr_pci_bridge_out(info);
            break;

        case pci_hdr_nonexistant:
            ret = true;
            break;

        default:
            bferror_nhex(0, "Unhandled PCI header:", pci_header_type(m_cf8));
            bferror_nhex(0, "m_cf8:", m_cf8);
            bferror_dump_cf8(0, m_cf8);
            bferror_lnbr(0); {
                const auto cf8 = ind(0xCF8);
                bferror_nhex(0, "0xCF8:", cf8);
                bferror_dump_cf8(0, cf8);
                bferror_lnbr(0);
            }
            bferror_nhex(0, "0xCFC:", ind(0xCFC));
            throw std::runtime_error("Unhandled PCI header");
    }

    //printf("data: %08lx\n", info.val);
    return ret;
}

bool
xen_op_handler::io_cfc_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    expects(info.port_number == 0xCFC);

//    debug_pci_out(m_cf8, info);
    return this->pci_out(info);
}

bool
xen_op_handler::io_cfd_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    expects(info.port_number == 0xCFD);

 //   debug_pci_out(m_cf8, info);
    return this->pci_out(info);
}

bool
xen_op_handler::io_cfe_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    expects(info.port_number == 0xCFE);

//    debug_pci_out(m_cf8, info);
    return this->pci_out(info);
}

bool
xen_op_handler::io_cfb_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    return false;
}

bool
xen_op_handler::io_cfb_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    expects(info.val == 1);
    return true;
}

static inline bool
vmware_guest(void)
{ return ::x64::cpuid::ebx::get(0x40000000) == 0x61774d56; }

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
    vcpu->advance();

    const auto pet_ticks = m_vcpu->get_vmx_preemption_timer();
    const auto tsc_ticks = pet_ticks << m_pet_shift;
    const auto uhz = m_tsc_freq_khz / 1000U;
    uint64_t usec = 1;

    if (uhz != 0) {
        usec = tsc_ticks / (uhz);
    }

    /// We clear Linux's sti blocking because we are sleeping from
    /// a hlt instruction. Linux does sti right before the hlt, so
    /// blocking_by_sti is set. If we don't clear it and try to inject
    /// later, VM-entry will fail.
    ///
    ::intel_x64::vmcs::guest_interruptibility_state::blocking_by_sti::disable();

    m_vcpu->disable_vmx_preemption_timer();
    m_vcpu->queue_timer_interrupt();
    m_vcpu->parent_vcpu()->load();
    m_vcpu->parent_vcpu()->return_yield(usec);

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

    //if (!vtd::frr_ready) {
    //    return;
    //}

    //if (::intel_x64::vtd::iommu::fsts_reg::ppf::is_enabled()) {
    //    printf("\n");
    //    bferror_info(0, "IOMMU fault occurred:");
    //    ::intel_x64::vtd::iommu::frr::dump(0);
    //    printf("\n");
    //}
}

bool
xen_op_handler::exit_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);

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

uint32_t
src_op_value(gsl::not_null<vcpu_t *> vcpu, int64_t src_op)
{
    switch (src_op) {
        case hyperkernel::intel_x64::insn_decoder::eax:
            return gsl::narrow_cast<uint32_t>(vcpu->rax()) & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::ecx:
            return gsl::narrow_cast<uint32_t>(vcpu->rcx()) & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::edx:
            return gsl::narrow_cast<uint32_t>(vcpu->rdx()) & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::ebx:
            return gsl::narrow_cast<uint32_t>(vcpu->rbx()) & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::esp:
            return gsl::narrow_cast<uint32_t>(vcpu->rsp()) & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::ebp:
            return gsl::narrow_cast<uint32_t>(vcpu->rbp()) & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::esi:
            return gsl::narrow_cast<uint32_t>(vcpu->rsi()) & 0xFFFFFFFFU;
        case hyperkernel::intel_x64::insn_decoder::edi:
            return gsl::narrow_cast<uint32_t>(vcpu->rdi()) & 0xFFFFFFFFU;
    }

    throw std::invalid_argument("invalid reg");
}

void
xen_op_handler::xapic_handle_write_icr(uint32_t low)
{
    using namespace eapis::intel_x64::lapic;

    const auto dlm = icr_low::delivery_mode::get(low);
    switch (dlm) {
        case icr_low::delivery_mode::fixed:
            break;
        default:
            bfalert_nhex(0, "unsupported delivery mode:", dlm);
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
xen_op_handler::xapic_handle_write_lvt_timer(uint32_t val)
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

    const auto idx = gsl::narrow_cast<uint32_t>(bfn::lower(info.gpa) >> 2);
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
xen_op_handler::rdmsr_mtrr_cap(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    ::x64::msrs::ia32_mtrrcap::vcnt::set(info.val, m_mtrr.size());
    ::x64::msrs::ia32_mtrrcap::fixed_range_mtrr::disable(info.val);
    ::x64::msrs::ia32_mtrrcap::wc::enable(info.val);
    ::x64::msrs::ia32_mtrrcap::smrr::disable(info.val);

    return true;
}

bool
xen_op_handler::rdmsr_mtrr_def(
    gsl::not_null<vcpu_t *>vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = m_mtrr_def;
    return true;
}

bool
xen_op_handler::rdmsr_mtrr_physbase(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    const auto msr_base = 0x200;
    expects((info.msr - msr_base) <= 6);
    expects(((info.msr - msr_base) & 1) == 0);

    const auto i = (info.msr - msr_base) >> 1;
    info.val = m_mtrr[i].base | m_mtrr[i].type;

    return true;
}

bool
xen_op_handler::rdmsr_mtrr_physmask(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::rdmsr_handler::info_t &info)
{
    bfignored(vcpu);

    const auto msr_base = 0x200;
    expects((info.msr - msr_base) <= 7);
    expects(((info.msr - msr_base) & 1) == 1);

    const auto i = (info.msr - msr_base) >> 1;
    info.val = size_to_physmask(m_mtrr[i].size);

    return true;
}

bool
xen_op_handler::wrmsr_mtrr_def(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    m_mtrr_def = info.val;
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
xen_op_handler::dom0_apic_base(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    ::intel_x64::msrs::ia32_apic_base::dump(0, info.val);
    info.ignore_write = false;
    return true;
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
//    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::mtrr::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::mca::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::ds::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::acpi::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::mmx::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::sse::mask;
    info.rdx &= ~::intel_x64::cpuid::feature_information::edx::sse2::mask;
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
    gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0;
    return true;
}

bool
xen_op_handler::io_ones_handler(
    gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    info.val = 0xFFFFFFFFFFFFFFFF;
    return true;
}

bool
xen_op_handler::io_ignore_handler(
    gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
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

        for (auto i = 0U; i < arg->nr_extents; i++) {
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
xen_op_handler::owns_current_bdf() const
{
    return m_nic == (m_cf8 & 0xFFFFFF00UL);
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

            m_mtrr.emplace_back(mtrr_range(entry));
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
                m_console = vcpu->map_gpa_4k<uint8_t>(XEN_CONSOLE_PAGE_GPA);
                arg->value = XEN_CONSOLE_PAGE_GPA >> x64::pt::page_shift;
                break;

            default:
                //bfdebug_info(0, "Unsupported HVM get_param:");
                //bfdebug_subnhex(0, "domid", arg->domid);
                //bfdebug_subnhex(0, "index", arg->index);
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
