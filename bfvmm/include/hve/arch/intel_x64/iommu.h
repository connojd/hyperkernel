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

    /// Dom0 init helper
    ///
    /// @expects
    /// @ensures
    ///
    void init_dom0_mappings(uintptr_t eptp);

    /// Add domain
    ///
    void add_domain(domainid_t id, uintptr_t eptp);

    /// Map in the given bus/device/function into the given domain
    ///
    void map(domainid_t id, uint32_t bus, uint32_t devfn);

    /// Enable DMA remapping
    ///
    void enable();

    /// Disable DMA remapping
    ///
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
    uint8_t *m_hva{};
    uintptr_t m_hpa{};

    page_ptr<entry_t> m_root;
    std::vector<page_ptr<entry_t>> m_ctxt_pages;

    // Store phys -> virt context page mappings
    std::unordered_map<uintptr_t, uintptr_t> m_ctxt_map;

    struct domain {
        domainid_t id;
        uintptr_t eptp;

        explicit domain(domainid_t id, uintptr_t eptp)
        {
            // arbitrary limit to prevent overflow in iommu::map
            expects(id < 128);
            expects(eptp != 0);

            this->id = id;
            this->eptp = eptp;
        }

        domain(domain &&) noexcept = delete;
        domain &operator=(domain &&) noexcept = delete;

        domain(const domain &) = delete;
        domain &operator=(const domain &) = delete;
    };

    std::unordered_map<domainid_t, std::unique_ptr<struct domain>> m_domains;
    uintptr_t domain_eptp(domainid_t id) const { return m_domains.at(id)->eptp; }

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
