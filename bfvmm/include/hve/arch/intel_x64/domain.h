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

#include "../../../domain/domain.h"

#include <eapis/hve/arch/intel_x64/apis.h>
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

    /// Get EAPIs vCPU Global State
    ///
    /// Return a pointer to the global vCPU state needed by the EAPIs.
    /// A pointer for this structure is needed for each vCPU that is
    /// created.
    ///
    gsl::not_null<eapis::intel_x64::eapis_vcpu_global_state_t*>
    eapis_vcpu_global_state()
    { return &m_eapis_vcpu_global_state; }



    /// Map 4k GPA to HPA
    ///
    /// Maps a 4k guest physical address to a 4k host physical address
    /// using EPT
    ///
    /// @expects
    /// @ensures
    ///
    /// @param virt_addr the virtual address to map from
    /// @param phys_addr the physical address to map to
    /// @param attr the map permissions
    /// @param cache the memory type for the mapping
    ///
    void map_4k(uintptr_t virt_addr, uintptr_t phys_addr);

    void map_commit();

    eapis::intel_x64::ept::mmap &ept()
    { return m_ept_map; }

    uintptr_t cr3()
    { return m_cr3_map.cr3(); }

    uintptr_t pat()
    { return m_cr3_map.pat(); }

    uintptr_t gdt_virt() const
    { return m_gdt_virt; }

    uintptr_t idt_virt() const
    { return m_idt_virt; }

    gsl::not_null<bfvmm::x64::gdt *> gdt()
    { return &m_gdt; }

    gsl::not_null<bfvmm::x64::idt *> idt()
    { return &m_idt; }

private:

    bfvmm::x64::tss m_tss{};
    bfvmm::x64::gdt m_gdt{512};
    bfvmm::x64::idt m_idt{256};

    uintptr_t m_tss_phys;
    uintptr_t m_gdt_phys;
    uintptr_t m_idt_phys;

    uintptr_t m_tss_virt;
    uintptr_t m_gdt_virt;
    uintptr_t m_idt_virt;

    bfvmm::x64::cr3::mmap m_cr3_map;
    eapis::intel_x64::ept::mmap m_ept_map;

    eapis::intel_x64::eapis_vcpu_global_state_t m_eapis_vcpu_global_state;

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
