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

#include "acpi.h"
#include "../../../domain/domain.h"
#include "../x64/mptable.h"

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
    void setup_nic();

private:

    bfvmm::x64::gdt m_gdt{512};
    bfvmm::x64::idt m_idt{256};

    uintptr_t m_tss_phys;
    uintptr_t m_gdt_phys;
    uintptr_t m_idt_phys;

    uintptr_t m_tss_virt;
    uintptr_t m_gdt_virt;
    uintptr_t m_idt_virt;

    std::vector<e820_entry_t> m_e820_map;

    eapis::intel_x64::ept::mmap m_ept_map;
    eapis::intel_x64::vcpu_global_state_t m_vcpu_global_state;

    page_ptr<bfvmm::x64::tss> m_tss;
    page_ptr<rsdp_t> m_rsdp;
    page_ptr<xsdt_t> m_xsdt;
    page_ptr<madt_t> m_madt;
    page_ptr<fadt_t> m_fadt;
    page_ptr<dsdt_t> m_dsdt;
    page_ptr<x64::mpfp_t> m_mpfp;

    static_assert(
        sizeof(x64::mpfp_t) + sizeof(x64::mp_table_t) < x64::pt::page_size
    );

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
