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

struct e820_map_entry_t {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
};

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

    /// Set up Dom0
    ///
    /// @expects
    /// @ensures
    ///
    void setup_dom0();

    /// Set up DomU
    ///
    /// @expects
    /// @ensures
    ///
    void setup_domU();

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
    void add_e820_entry(const e820_map_entry_t &entry);

public:

    /// Map 1g GPA to HPA
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
    void map_1g(uintptr_t gpa, uintptr_t hpa);

    /// Map 2m GPA to HPA
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
    void map_2m(uintptr_t gpa, uintptr_t hpa);

    /// Map 4k GPA to HPA
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
    void map_4k(uintptr_t gpa, uintptr_t hpa);

    /// Convert GPA to HPA
    ///
    /// Converts a guest physical address to a host physical address
    /// using EPT.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return the resulting host physical address
    ///
    std::pair<uintptr_t, uintptr_t> gpa_to_hpa(uint64_t gpa);

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(uintptr_t gpa)
    {
        auto [hpa, unused] = this->gpa_to_hpa(gpa);
        return bfvmm::x64::map_hpa_1g<T>(hpa);
    }

    /// Map GPA (1g)
    ///
    /// Map a 1g guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 1g page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_1g(void *gpa)
    { return map_gpa_1g<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(uintptr_t gpa)
    {
        auto [hpa, unused] = this->gpa_to_hpa(gpa);
        return bfvmm::x64::map_hpa_2m<T>(hpa);
    }

    /// Map GPA (2m)
    ///
    /// Map a 2m guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 2m page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_2m(void *gpa)
    { return map_gpa_2m<T>(reinterpret_cast<uintptr_t>(gpa)); }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(uintptr_t gpa)
    {
        auto [hpa, unused] = this->gpa_to_hpa(gpa);
        return bfvmm::x64::map_hpa_4k<T>(hpa);
    }

    /// Map GPA (4k)
    ///
    /// Map a 4k guest physical address. The result of this function is a
    /// unique_map that will unmap when scope is lost
    ///
    /// @expects gpa is 4k page aligned
    /// @expects gpa != 0
    /// @ensures
    ///
    /// @param gpa the guest physical address
    /// @return a unique_map that can be used to access the gpa
    ///
    template<typename T>
    auto map_gpa_4k(void *gpa)
    { return map_gpa_4k<T>(reinterpret_cast<uintptr_t>(gpa)); }

public:

    gsl::not_null<bfvmm::x64::gdt *> gdt()
    { return &m_gdt; }

    gsl::not_null<bfvmm::x64::idt *> idt()
    { return &m_idt; }

    uintptr_t gdt_virt() const
    { return m_gdt_virt; }

    uintptr_t idt_virt() const
    { return m_idt_virt; }

    std::vector<e820_map_entry_t> &e820_map()
    { return m_e820_map; }

    eapis::intel_x64::ept::mmap &ept()
    { return m_ept_map; }

    gsl::not_null<eapis::intel_x64::vcpu_global_state_t*>
    global_state()
    { return &m_vcpu_global_state; }

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

    std::vector<e820_map_entry_t> m_e820_map;

    eapis::intel_x64::ept::mmap m_ept_map;
    eapis::intel_x64::vcpu_global_state_t m_vcpu_global_state;

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
