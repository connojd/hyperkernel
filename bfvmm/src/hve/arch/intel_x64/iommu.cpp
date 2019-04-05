//
// Bareflank Extended APIs
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

#include <bfgsl.h>
#include <intrinsics.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <bfvmm/memory_manager/arch/x64/cr3.h>
#include <eapis/hve/arch/x64/unmapper.h>
#include <eapis/hve/arch/intel_x64/vtd/iommu.h>
#include <hve/arch/intel_x64/iommu.h>
#include <hve/arch/intel_x64/pci.h>

using namespace eapis::intel_x64;
using namespace bfvmm::x64;

extern void *g_dmar;

namespace hyperkernel::intel_x64
{

iommu::iommu() : m_root{make_page<entry_t>()}
{
    if (!g_dmar) {
        throw std::runtime_error("DMAR pointer is NULL");
    }

    const auto dmar = (const char *)g_dmar;
    const auto size = *(uint32_t *)(dmar + 4);
    const auto haw = *(uint8_t *)(dmar + 36) + 1;
    const auto flags = *(uint8_t *)(dmar + 37);

    const char *rs = dmar + (uintptr_t)48;
    const char *end = dmar + (uintptr_t)size;

    while (rs < end) {
        const auto rs_type = *(uint16_t *)rs;
        const auto rs_size = *(uint16_t *)(rs + 2);

        if (rs_type != 0) {

            // Actually we should never get here if the table is
            // well formed; the remapping structures are sorted by
            // type, with DRHD being the first

            expects(rs_type == 0);
            rs += (uintptr_t)rs_size;
            continue;
        }

        const auto rs_flag = *(uint8_t *)(rs + 4);
        const auto rs_base = *(uint64_t *)(rs + 8);

        // Once we hit a DRHD with INCLUDE_PCI_ALL set, that
        // means we've processed every other DRHD. Each previous
        // DRHD did not scope the device of interest, so it is
        // included in this catch-all entry per section 8.3 of the spec

        if ((rs_flag & 0x1) == 1) {
            m_hpa = rs_base;
            break;
        }

        // Process each device scope entry to check if
        // it scopes the device of interest

        const char *dse = rs + (uintptr_t)16;
        while (dse < (rs + rs_size)) {
            const auto dse_size = *(dse + (uintptr_t)1);

            if (*dse != 0x1) {
                dse += (uintptr_t)dse_size;
                continue;
            }

            auto num = (dse_size - 6) / 2; // number of path pairs
            auto i = 0;
            expects(i < num);

            uint16_t *path = (uint16_t *)(dse + (uintptr_t)6);
            uint32_t bus = *(dse + (uintptr_t)5);
            uint32_t dev = path[i] & 0xFF;
            uint32_t fun = (path[i] & 0xFF00) >> 8;

            for (i += 1; i < num; i++) {
                bus = secondary_bus(bus, dev, fun);
                dev = path[i] & 0xFF;
                fun = (path[i] & 0xFF00) >> 8;
            }

            if (domU_owned_cf8(bdf_to_cf8(bus, dev, fun))) {
                m_hpa = rs_base;
                goto hpa_found;
            }

            dse += (uintptr_t)dse_size;
        }

        rs += rs_size;
    }

hpa_found:

    bfdebug_nhex(0, "DRHD base:", m_hpa);

    /// Map in registers
    ///
    auto hva = g_mm->alloc_map(iommu::page_size);

    g_cr3->map_4k(
            hva,
            m_hpa,
            cr3::mmap::attr_type::read_write,
            cr3::mmap::memory_type::uncacheable);

    m_reg_map = eapis::x64::unique_map<uint8_t>(
            static_cast<uint8_t *>(hva),
            eapis::x64::unmapper(hva, iommu::page_size)
    );
}

iommu *iommu::instance() noexcept
{
    static iommu self;
    return &self;
}

void iommu::add_domain(domainid_t domid, uintptr_t eptp)
{
    bfdebug_info(0, "Adding domain:");
    bfdebug_subnhex(0, "id", domid);
    bfdebug_subnhex(0, "eptp", eptp);

    m_domains.emplace(domid, std::make_unique<struct domain>(domid, eptp));
}

void iommu::map(domainid_t domid, uint32_t bus, uint32_t devfn)
{
    expects(bus < 256);
    expects(devfn < 256);

//    bfdebug_info(0, "IOMMU map:");
//    bfdebug_subnhex(0, "bus", bus);
//    bfdebug_subnhex(0, "devfn", devfn);

    entry_t *rte = &m_root.get()[bus];

    if (rte->data[0] == 0) {
        auto ctxt = make_page<entry_t>();
        auto virt = ctxt.get();
        auto phys = g_mm->virtptr_to_physint(virt);

        // Enable passthrough of the bus
        rte->data[0] = phys | 1U;

        // Save a mapping for the context page
        m_ctxt_map.emplace(phys, reinterpret_cast<uintptr_t>(virt));

        // Move the context page to its owner
        m_ctxt_pages.push_back(std::move(ctxt));
    }
    ensures(rte->data[0] != 0);

    // Lookup the hva of the context page
    entry_t *hva = reinterpret_cast<entry_t *>(m_ctxt_map.at(rte->data[0] & ~0xFFFULL));
    entry_t *cte = &hva[devfn];

    // Make devfn present, point to domain's eptp
    cte->data[0] = domain_eptp(domid) | 1U;

    // Set domid and 4-level EPT translation; domid 0 is reserved by the VT-d
    // spec, so add one to every id first.
    cte->data[1] = ((domid + 1) << 8) | 2U;

    ::x64::cache::wbinvd();
}

void iommu::init_dom0_mappings(uintptr_t eptp)
{
    this->add_domain(0, eptp);

    // Bus 0
    this->map(0, 0, devfn(0x00, 0x00)); // Host bridge
    this->map(0, 0, devfn(0x02, 0x00)); // VGA
    this->map(0, 0, devfn(0x08, 0x00)); // Gaussian model
    this->map(0, 0, devfn(0x14, 0x00)); // USB
    this->map(0, 0, devfn(0x16, 0x00)); // Comms
    this->map(0, 0, devfn(0x17, 0x00)); // SATA
    this->map(0, 0, devfn(0x1B, 0x00)); // PCI Bridge to bus 1
    this->map(0, 0, devfn(0x1C, 0x00)); // PCI Bridge to bus 2
    this->map(0, 0, devfn(0x1C, 0x05)); // PCI Bridge to bus 3
    this->map(0, 0, devfn(0x1C, 0x06)); // PCI Bridge to bus 4
    this->map(0, 0, devfn(0x1C, 0x07)); // PCI Bridge to bus 5
    this->map(0, 0, devfn(0x1D, 0x00)); // PCI Bridge to bus 6
    this->map(0, 0, devfn(0x1D, 0x01)); // PCI Bridge to bus 7
    this->map(0, 0, devfn(0x1D, 0x02)); // PCI Bridge to bus 8
    this->map(0, 0, devfn(0x1D, 0x03)); // PCI Bridge to bus 9
    this->map(0, 0, devfn(0x1F, 0x00)); // ISA bridge
    this->map(0, 0, devfn(0x1F, 0x02)); // Memory controller
    this->map(0, 0, devfn(0x1F, 0x03)); // Audio controller
    this->map(0, 0, devfn(0x1F, 0x04)); // SMBus controller

    // Bus 1
    this->map(0, 1, devfn(0x00, 0x00));

    ::x64::cache::wbinvd();
}

void iommu::enable()
{
    m_hva = m_reg_map.get();

    auto ecap = this->read64(0x10);
    auto gsts = this->read32(0x1C);
    auto rtar = this->read64(0x20);

//    ::intel_x64::vtd::iommu::cap_reg::dump(0, cap);
//    ::intel_x64::vtd::iommu::ecap_reg::dump(0, ecap);
//    ::intel_x64::vtd::iommu::rtaddr_reg::dump(0, rtar);
//    ::intel_x64::vtd::iommu::gsts_reg::dump(0, gsts);

//    if (::intel_x64::vtd::iommu::gsts_reg::tes::is_disabled(gsts)) {
//        //reset_nic();
//        this->disable();
//    }

    expects(::intel_x64::vtd::iommu::gsts_reg::tes::is_disabled(gsts));
    expects(::intel_x64::vtd::iommu::gsts_reg::qies::is_disabled(gsts));
    expects(::intel_x64::vtd::iommu::gsts_reg::ires::is_disabled(gsts));

    //
    // Set the root address with legacy translation mode
    //

    this->write64(0x20, g_mm->virtptr_to_physint(m_root.get()));
    ::intel_x64::barrier::mb();
    gsts = this->read32(0x1C);
    uint32_t gcmd = (gsts & 0x96FFFFFFU) | (1UL << 30);
    this->write32(0x18, gcmd);

    ::intel_x64::barrier::mb();
    while ((this->read32(0x1C) | (1UL << 30)) == 0) {
        ::intel_x64::pause();
    }

    //
    // Once the RTAR is set, the context-cache and IOTLB must be invalidated
    //

    uint64_t ctxcmd = this->read64(0x28);
    expects((ctxcmd & 0x8000000000000000U) == 0);
    ctxcmd &= ~0x6000000000000000U;
    ctxcmd |= (1ULL << 61); // global invalidation
    ctxcmd |= (1ULL << 63); // do it
    this->write64(0x28, ctxcmd);

    ::intel_x64::barrier::mb();
    while ((this->read64(0x28) & (1ULL << 63)) != 0) {
        ::intel_x64::pause();
    }

    uint64_t iva = ::intel_x64::vtd::iommu::ecap_reg::iro::get(ecap);
    expects(iva == 0x50);
    uint64_t iotlb = this->read64(iva + 0x8);
    iotlb &= ~0x3000000000000000U;
    iotlb |= (1ULL << 60); // global invalidation
    iotlb |= (1ULL << 63); // do it
    this->write64(iva + 0x8, iotlb);

    ::intel_x64::barrier::mb();
    while ((this->read64(iva + 0x8) & (1ULL << 63)) != 0) {
        ::intel_x64::pause();
    }

    //
    // Enable DMA remapping
    //

    gsts = this->read32(0x1C);
    gcmd = (gsts & 0x96FFFFFFU) | (1UL << 31);
    this->write32(0x18, gcmd);

    ::intel_x64::barrier::mb();
    while ((this->read32(0x1C) | (1UL << 31)) == 0) {
        ::intel_x64::pause();
    }
}

void iommu::disable()
{
    uint32_t gsts = this->read32(0x1C);
    uint32_t gcmd = (gsts & 0x16FFFFFFU);
    this->write32(0x18, gcmd);

    ::intel_x64::barrier::mb();
    while ((this->read32(0x1C) & (1UL << 31)) != 0) {
        ::intel_x64::pause();
    }
}

/// Register access
///
uint64_t iommu::read64(uintptr_t off)
{
    uint64_t *addr = reinterpret_cast<uint64_t *>(m_hva + off);
    return *addr;
}

uint32_t iommu::read32(uintptr_t off)
{
    uint32_t *addr = reinterpret_cast<uint32_t *>(m_hva + off);
    return *addr;
}

void iommu::write64(uintptr_t off, uint64_t val)
{
    uint64_t *addr = reinterpret_cast<uint64_t *>(m_hva + off);
    *addr = val;
}

void iommu::write32(uintptr_t off, uint64_t val)
{
    uint32_t *addr = reinterpret_cast<uint32_t *>(m_hva + off);
    *addr = gsl::narrow_cast<uint32_t>(val);
}

}
