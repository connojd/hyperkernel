//
// Bareflank Hyperkernel
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <debug.h>
#include <upper_lower.h>
#include <vector>
#include <algorithm>

#include <domain/domain_intel_x64.h>
#include <process/process_intel_x64.h>

#include <memory_manager/map_ptr_x64.h>
#include <memory_manager/memory_manager_x64.h>

using namespace x64;
using namespace intel_x64;

void map_phys__direct(std::vector<uintptr_t>& addr)
{
    (void) addr;
    return;
}

//void map_phys__alternate(std::vector<uintptr_t>& addr)
//{
//    auto nr_hugepages = addr.size() / 512;
//
//    for (int i = 0; i < 512; i++) {
//        uintptr_t tmp = addr[i];
//        addr[i] = addr[i % nr_hugepages * 512];
//        addr[i * 512] = tmp;
//    }
//
//
//
//
//}

void map_phys__shuffle(std::vector<uintptr_t>& addr)
{
    std::random_shuffle(addr.begin(), addr.end());
}

process_intel_x64::process_intel_x64(
    processid::type id,
    gsl::not_null<domain_intel_x64 *> domain) :

    process(id),

    m_domain(domain),
    m_root_ept(std::make_unique<root_ept_intel_x64>())
{ }

void
process_intel_x64::init(user_data *data)
{
    m_root_ept->map_4k(m_domain->tss_base_virt(), m_domain->tss_base_phys(), ept::memory_attr::rw_wb);
    m_root_ept->map_4k(m_domain->gdt_base_virt(), m_domain->gdt_base_phys(), ept::memory_attr::ro_wb);
    m_root_ept->map_4k(m_domain->idt_base_virt(), m_domain->idt_base_phys(), ept::memory_attr::ro_wb);

    auto &&list = m_domain->cr3_mdl();

//    bfdebug << "process init: cr3_mdl size = " << list.size() << bfendl;
    for (auto md : list) {
//        bfdebug << "    md.phys = 0x" << std::hex << md.phys << bfendl;
//        bfdebug << "    md.virt = 0x" << std::hex << md.virt << bfendl;
//        bfdebug << "    md.type = " << md.type << bfendl;
        m_root_ept->map_4k(md.phys, md.phys, ept::memory_attr::rw_wb);
    }

 //   auto ept_list = m_root_ept->ept_to_mdl();
 //   bfdebug << "process init: ept_mdl size = " << ept_list.size() << bfendl;
 //   for (auto md : ept_list) {
 //       bfdebug << "    md.phys = 0x" << std::hex << md.phys << bfendl;
 //       bfdebug << "    md.virt = 0x" << std::hex << md.virt << bfendl;
 //       bfdebug << "    md.type = " << md.type << bfendl;
 //   }

    process::init(data);
}

void
process_intel_x64::fini(user_data *data)
{ process::fini(data); }

void
process_intel_x64::vm_map(
    uintptr_t virt,
    uintptr_t phys,
    uintptr_t size,
    uintptr_t perm)
{
    // TODO: Should enforce page alignement, and a multiple of a page.
    //       This is a safety measure to ensure that no memory is ever
    //       leaked.

    // bfdebug << "[process #" << id() << "]: mapping virtual memory\n";
    // bfdebug << "  - virt: " << view_as_pointer(virt) << '\n';
    // bfdebug << "  - phys: " << view_as_pointer(phys) << '\n';
    // bfdebug << "  - size: " << view_as_pointer(size) << '\n';
    // bfdebug << "  - perm: " << view_as_pointer(perm) << '\n';

    // TODO: Remove me
    //
    size += bfn::lower(virt);

    for (auto page = 0UL; page < size; page += ept::pt::size_bytes)
        this->vm_map_page(virt + page, phys + page, perm);
}

void
process_intel_x64::vm_map_lookup(
    uintptr_t virt,
    uintptr_t rtpt,
    uintptr_t addr,
    uintptr_t size,
    uintptr_t perm)
{
    // TODO: Should enforce page alignement, and a multiple of a page.
    //       This is a safety measure to ensure that no memory is ever
    //       leaked.

    // bfdebug << "[process #" << id() << "]: mapping virtual memory\n";
    // bfdebug << "  - rtpt: " << view_as_pointer(rtpt) << '\n';
    // bfdebug << "  - virt: " << view_as_pointer(virt) << '\n';
    // bfdebug << "  - addr: " << view_as_pointer(addr) << '\n';
    // bfdebug << "  - size: " << view_as_pointer(size) << '\n';
    // bfdebug << "  - perm: " << view_as_pointer(perm) << '\n';

    // TODO: Remove me
    //
    size += bfn::lower(virt);

    for (auto page = 0UL; page < size; page += ept::pt::size_bytes)
    {
        auto &&phys = bfn::virt_to_phys_with_cr3(addr + page, rtpt);
        this->vm_map_page(virt + page, phys, perm);
    }
}

void
process_intel_x64::vm_map_lookup_2m(
    uintptr_t gpa,
    uintptr_t rtpt,
    uintptr_t addr,
    uintptr_t size,
    uintptr_t perm)
{
    bool use_hugepages = gpa & 0x1;
    uint64_t phys_mapping = (gpa & 0xe) >> 1;
    gpa &= ~0xfULL;
    size_t page_sz = (use_hugepages) ? ept::pd::size_bytes : ept::pt::size_bytes;
    size_t npages = size / page_sz;

    std::vector<uintptr_t> phys_addrs;
    for (auto i = 0UL; i < npages; i++) {
        phys_addrs.push_back(bfn::virt_to_phys_with_cr3(addr + i * page_sz, rtpt));
    }

    if (!use_hugepages) {
        switch (phys_mapping) {
            case 0: map_phys__direct(phys_addrs); break;
            case 1: map_phys__shuffle(phys_addrs); break;
            default: throw std::invalid_argument("invalid phys_mapping\n");
        }
    }

    for (auto i = 0UL; i < npages; i++) {
        this->vm_map_page_2m(gpa + i * page_sz, phys_addrs[i], perm);
    }
}

void
process_intel_x64::vm_map_page_2m(
    uintptr_t virt,
    uintptr_t phys,
    uintptr_t perm)
{
    (void) perm;

    m_root_ept->map_2m(virt, phys, ept::memory_attr::pt_wb);
}

void
process_intel_x64::vm_map_page(
    uintptr_t virt,
    uintptr_t phys,
    uintptr_t perm)
{
    // TODO: We need to use the permission flags to determine how to
    // actually map memory

    (void) perm;

    m_root_ept->map_4k(virt, phys, ept::memory_attr::pt_wb);
}
