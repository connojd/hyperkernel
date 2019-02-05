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
#include <hve/arch/intel_x64/iommu.h>

namespace hyperkernel::intel_x64
{

iommu::iommu() noexcept
{
    /// Map in registers
    ///
    auto hva = g_mm->alloc_map(iommu::page_size);
    g_cr3->map_4k(hva, iommu::hpa);
    m_reg_map = eapis::x64::unique_map<uint8_t>(
        static_cast<uint8_t *>(hva),
        eapis::x64::unmapper(hva, iommu::page_size)
    );
    m_reg_hva = m_reg_map.get();
}

iommu *iommu::instance() noexcept
{
    static iommu self;
    return &self;
}

static void set_dom0_cte(iommu::entry_t *cte, eapis::intel_x64::ept::mmap *mmap)
{
    // TODO check TT against dev tlb support
    cte->data[0] = mmap->eptp() | 1U; // present, points to dom0 ept
    cte->data[1] = (1ULL << 8U) | 2U; // DID 1, 4-level EPT
}

// Called once from dom0, vcpu0
//
void iommu::init_dom0()
{
    // Allocate root and ctxt (one for each bus)
    m_root = make_page<entry_t>();
    m_ctxt[0] = make_page<entry_t>();
    m_ctxt[1] = make_page<entry_t>();
    m_ctxt[2] = make_page<entry_t>();

    // Setup root entries
    entry_t *rte = m_root.get();
    rte[0].data[0] = g_mm->virtptr_to_physint(m_ctxt[0].get()) | 1U;
    rte[1].data[0] = g_mm->virtptr_to_physint(m_ctxt[1].get()) | 1U;
    rte[2].data[0] = g_mm->virtptr_to_physint(m_ctxt[2].get()) | 1U;

    // Bus 0
    entry_t *cte = m_ctxt[0].get();
    set_dom0_cte(&cte[0], mmap); // devfn 0





}

/// Register access
///
uint64_t iommu::read64(uintptr_t off)
{
    auto addr = reinterpret_cast<uint64_t *>(m_reg_hva + off);
    return *addr;
}

uint32_t iommu::read32(uintptr_t off)
{
    auto addr = reinterpret_cast<uint32_t *>(m_reg_hva + off);
    return *addr;
}

void iommu::write64(uintptr_t off, uint64_t val)
{
    auto addr = reinterpret_cast<uint64_t *>(m_reg_hva + off);
    *addr = val;
}

void iommu::write32(uintptr_t off, uint64_t val)
{
    auto addr = reinterpret_cast<uint32_t *>(m_reg_hva + off);
    *addr = gsl::narrow_cast<uint32_t>(val);
}

}
