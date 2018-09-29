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

#include <bfdebug.h>
#include <hve/arch/intel_x64/domain.h>

namespace hyperkernel::intel_x64
{

domain::domain(domainid_type domainid) :
    hyperkernel::domain{domainid}
{
    using namespace ::x64::access_rights;

    using namespace bfvmm::x64;
    using namespace eapis::intel_x64;

    m_gdt_phys = g_mm->virtint_to_physint(m_gdt.base());
    m_idt_phys = g_mm->virtint_to_physint(m_idt.base());
    m_tss_phys = g_mm->virtptr_to_physint(&m_tss);

    m_gdt_virt = 0x1000;
    m_idt_virt = 0x2000;
    m_tss_virt = 0x3000;

    m_gdt.set(1, nullptr, 0xFFFFFFFF, ring0_cs_descriptor);
    m_gdt.set(2, nullptr, 0xFFFFFFFF, ring0_ss_descriptor);
    m_gdt.set(3, nullptr, 0xFFFFFFFF, ring0_fs_descriptor);
    m_gdt.set(4, nullptr, 0xFFFFFFFF, ring0_gs_descriptor);
    m_gdt.set(5, m_tss_virt, sizeof(m_tss), ring0_tr_descriptor);

    m_cr3_map.map_4k(m_gdt_virt, m_gdt_virt, cr3::mmap::attr_type::read_write);
    m_cr3_map.map_4k(m_idt_virt, m_idt_virt, cr3::mmap::attr_type::read_write);
    m_cr3_map.map_4k(m_tss_virt, m_tss_virt, cr3::mmap::attr_type::read_write);

    m_ept_map.map_4k(m_tss_virt, m_tss_phys, ept::mmap::attr_type::read_write);
    m_ept_map.map_4k(m_gdt_virt, m_gdt_phys, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(m_idt_virt, m_idt_phys, ept::mmap::attr_type::read_only);

    for (auto iter = m_cr3_map.mdl().begin(); iter != m_cr3_map.mdl().end(); iter++) {
        m_ept_map.map_4k(iter->second, iter->second, ept::mmap::attr_type::read_write);
    }

    auto cr3_phys = bfn::upper(m_cr3_map.cr3());
    m_ept_map.map_4k(cr3_phys, cr3_phys, ept::mmap::attr_type::read_write);
}

void
domain::map_4k(uintptr_t virt_addr, uintptr_t phys_addr)
{
    using namespace bfvmm::x64;
    using namespace eapis::intel_x64;

    m_ept_map.map_4k(virt_addr, phys_addr, ept::mmap::attr_type::read_write_execute);
    m_cr3_map.map_4k(virt_addr, virt_addr, cr3::mmap::attr_type::read_write_execute);
}

}
