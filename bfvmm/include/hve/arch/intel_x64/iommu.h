//
// Bareflank Hyperkernel
// Copyright (C) 2019 Assured Information Security, Inc.
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

#ifndef IOMMU_INTEL_X64_HYPERKERNEL_H
#define IOMMU_INTEL_X64_HYPERKERNEL_H

#include <cstdint>
#include <eapis/hve/arch/x64/unmapper.h>
#include <hve/arch/intel_x64/vcpu.h>

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

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

namespace vtd {
    extern uint64_t visr_vector;
    extern uint64_t ndvm_vector;
    extern uint64_t ndvm_apic_id;
    extern uint64_t ndvm_vcpu_id;
}

namespace hyperkernel::intel_x64 {

class EXPORT_HYPERKERNEL_HVE iommu
{
public:

    using entry_t = struct { uint64_t data[2]; } __attribute__((packed));

    /// Only 4K pages allowed
    ///
    static constexpr uintptr_t page_size = 4096UL;

    /// Get the instance of the iommu
    ///
    static iommu *instance() noexcept;

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~iommu() = default;

    /// Initialize
    ///
    /// @expects
    /// @ensures
    ///
    void init_dom0_mappings();
    void init_domU_mappings();

    void set_dom0_eptp(uintptr_t eptp);
    void set_domU_eptp(uintptr_t eptp);

    void set_dom0_cte(entry_t *cte);
    void set_domU_cte(entry_t *cte);

    void enable();
    void disable();

    /// Register access
    ///
    uint64_t read64(uintptr_t off);
    uint32_t read32(uintptr_t off);
    void write64(uintptr_t off, uint64_t val);
    void write32(uintptr_t off, uint64_t val);

private:

    iommu();
    eapis::x64::unique_map<uint8_t> m_reg_map;
    uintptr_t m_dom0_eptp{0};
    uintptr_t m_domU_eptp{0};

    page_ptr<entry_t> m_root;
    std::vector<page_ptr<entry_t>> m_ctxt;
    uint8_t *m_hva{};
    uintptr_t m_hpa{};

public:

    /// @cond

    iommu(iommu &&) noexcept = delete;
    iommu &operator=(iommu &&) noexcept = delete;

    iommu(const iommu &) = delete;
    iommu &operator=(const iommu &) = delete;

    /// @endcond
};
}

/// iommu macro
///
/// The following macro can be used to quickly call for iommu services
///
/// @expects
/// @ensures g_iommu != nullptr
///
#define g_iommu hyperkernel::intel_x64::iommu::instance()

#endif
