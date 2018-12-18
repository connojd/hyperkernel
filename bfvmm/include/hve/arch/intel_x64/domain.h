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

#ifndef DOMAIN_INTEL_X64_HYPERKERNEL_H
#define DOMAIN_INTEL_X64_HYPERKERNEL_H

#include <vector>
#include <memory>

#include "acpi.h"
#include "uart.h"
#include "../../../domain/domain.h"

#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/memory_manager/arch/x64/cr3.h>

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

struct e820_entry_t {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} __attribute__((packed));

class vcpu;

/// Domain
///
class EXPORT_HYPERKERNEL_HVE domain : public hyperkernel::domain
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    domain(domainid_type domainid);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~domain() = default;

public:

    /// Map 1g GPA to HPA (Read-Only)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read-Only)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read-Only)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_ro(uintptr_t gpa, uintptr_t hpa);

    /// Map 1g GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Wrtie)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_rw(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Write, Uncacheable)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_rw_uc(uintptr_t gpa, uintptr_t hpa);

    /// Map 1g GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 1g guest physical address to a 1g host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_1g_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 2m guest physical address to a 2m host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_2m_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA (Read/Write/Execute)
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @param hpa the host physical address
    ///
    void map_4k_rwe(uintptr_t gpa, uintptr_t hpa);

    /// Unmap GPA
    ///
    /// Unmaps a guest physical address
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address to unmap
    ///
    void unmap(uintptr_t gpa);

    /// Release Virtual Address
    ///
    /// Returns any unused page tables back to the heap, releasing memory and
    /// providing a means to reconfigure the granularity of a previous mapping.
    ///
    /// @note that unmap must be run for any existing mappings, otherwise this
    ///     function has no effect.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the address to release
    ///
    void release(uintptr_t gpa);

public:

    /// Add E820 Map Entry
    ///
    /// Adds an E820 map entry to the list. This is populated by the domain
    /// builder, which is them provided to the guest on demand through the
    /// vmcall interface
    ///
    /// @expects
    /// @ensures
    ///
    /// @param entry the E820 map entry to add
    ///
    void add_e820_entry(const e820_entry_t &entry);

    /// Set UART
    ///
    /// If set, enables the use of an emulated UART that will be created
    /// during the vCPU's construction
    ///
    /// @expects
    /// @ensures
    ///
    /// @param uart the port of the serial device to emulate
    ///
    void set_uart(uart::port_type uart) noexcept;

    /// Set Pass-Through UART
    ///
    /// If set, passes through a UART to the VM during each vCPU's
    /// construction.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param uart the port of the serial device to pass through
    ///
    void set_pt_uart(uart::port_type uart) noexcept;

    /// Setup vCPU UARTs
    ///
    /// Given a vCPU, this function will setup all of the UARTs based
    /// on how the domain have been configured.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vCPU to setup
    ///
    void setup_vcpu_uarts(gsl::not_null<vcpu *> vcpu);

    /// Dump UART
    ///
    /// Dumps the contents of the active UART to a provided buffer. Either
    /// set_uart or set_pt_uart must be executed for this function to
    /// succeed
    ///
    /// @expects
    /// @ensures
    ///
    /// @param buffer the buffer to dump the contents of the UART into
    /// @return the number of bytes transferred to the buffer
    ///
    uint64_t dump_uart(const gsl::span<char> &buffer);

public:

    gsl::not_null<bfvmm::x64::gdt *> gdt()
    { return &m_gdt; }

    gsl::not_null<bfvmm::x64::idt *> idt()
    { return &m_idt; }

    uintptr_t gdt_virt() const
    { return m_gdt_virt; }

    uintptr_t idt_virt() const
    { return m_idt_virt; }

    std::vector<e820_entry_t> &e820_map()
    { return m_e820_map; }

    eapis::intel_x64::ept::mmap &ept()
    { return m_ept_map; }

    gsl::not_null<eapis::intel_x64::vcpu_global_state_t*>
    global_state()
    { return &m_vcpu_global_state; }

private:

    void setup_dom0();
    void setup_domU();

    void setup_acpi();

private:

    bfvmm::x64::gdt m_gdt{512};
    bfvmm::x64::idt m_idt{256};

    uint64_t m_tss_phys{};
    uint64_t m_gdt_phys{};
    uint64_t m_idt_phys{};

    uint64_t m_tss_virt{};
    uint64_t m_gdt_virt{};
    uint64_t m_idt_virt{};

    std::vector<e820_entry_t> m_e820_map;

    eapis::intel_x64::ept::mmap m_ept_map;
    eapis::intel_x64::vcpu_global_state_t m_vcpu_global_state;

    page_ptr<bfvmm::x64::tss> m_tss;
    page_ptr<rsdp_t> m_rsdp;
    page_ptr<xsdt_t> m_xsdt;
    page_ptr<madt_t> m_madt;
    page_ptr<fadt_t> m_fadt;
    page_ptr<dsdt_t> m_dsdt;

    uart::port_type m_uart_port{};
    uart::port_type m_pt_uart_port{};
    uart m_uart_3F8{0x3F8};
    uart m_uart_2F8{0x2F8};
    uart m_uart_3E8{0x3E8};
    uart m_uart_2E8{0x2E8};
    std::unique_ptr<uart> m_pt_uart;

public:

    /// @cond

    domain(domain &&) = default;
    domain &operator=(domain &&) = default;

    domain(const domain &) = delete;
    domain &operator=(const domain &) = delete;

    /// @endcond
};

}

/// Get Domain
///
/// Gets a domain from the domain manager given a domain id
///
/// @expects
/// @ensures
///
/// @return returns a pointer to the domain being queried or throws
///     and exception.
///
#define get_domain(a) \
    g_dm->get<hyperkernel::intel_x64::domain *>(a, "invalid domainid: " __FILE__)

#endif
