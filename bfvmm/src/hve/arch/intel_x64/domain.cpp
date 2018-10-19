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

using namespace eapis::intel_x64;

namespace hyperkernel::intel_x64
{

domain::domain(domainid_type domainid) :
    hyperkernel::domain{domainid}
{
    if (domainid == 0) {
        setup_dom0();
    }
    else {
        setup_domU();
    }
}

void
domain::setup_dom0()
{
    ept::identity_map(
        m_ept_map, MAX_PHYS_ADDR
    );
}

void
domain::setup_domU()
{
    using namespace ::x64::access_rights;

    m_gdt_phys = g_mm->virtint_to_physint(m_gdt.base());
    m_idt_phys = g_mm->virtint_to_physint(m_idt.base());
    m_tss_phys = g_mm->virtptr_to_physint(&m_tss);

    m_gdt_virt = 0x1000;
    m_idt_virt = 0x2000;
    m_tss_virt = 0x3000;

    m_gdt.set(2, nullptr, 0xFFFFFFFF, 0xc09b);
    m_gdt.set(3, nullptr, 0xFFFFFFFF, 0xc093);
    m_gdt.set(4, m_tss_virt, sizeof(m_tss), 0x008b);

    m_ept_map.map_4k(m_tss_virt, m_tss_phys, ept::mmap::attr_type::read_write);
    m_ept_map.map_4k(m_gdt_virt, m_gdt_phys, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(m_idt_virt, m_idt_phys, ept::mmap::attr_type::read_only);
}

void
domain::map_1g(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa); }

void
domain::map_2m(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa); }

void
domain::map_4k(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa); }

void
domain::add_e820_entry(const e820_map_entry_t &entry)
{ m_e820_map.emplace_back(entry); }

}
