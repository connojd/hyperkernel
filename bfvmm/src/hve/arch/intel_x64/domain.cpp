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
#include <bfcallonce.h>
#include <bfgpalayout.h>

#include <hve/arch/intel_x64/domain.h>
#include <hve/arch/intel_x64/iommu.h>

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

bfn::once_flag init_iommu;

namespace hyperkernel::intel_x64
{

domain::domain(domainid_type domainid) :
    hyperkernel::domain{domainid},
    m_tss{make_page<bfvmm::x64::tss>()},
    // TODO: these must be powers of two
    m_rsdp{make_page<rsdp_t>()},
    m_xsdt{make_page<xsdt_t>()},
    m_madt{make_page<madt_t>()},
    m_fadt{make_page<fadt_t>()},
    m_dsdt{make_page<dsdt_t>()},
    m_mcfg{make_page<mcfg_t>()}
{
    if (domainid == 0) {
        this->setup_dom0();
        bfn::call_once(init_iommu, [&]() {
            g_iommu->set_dom0_eptp(m_ept_map.eptp());
            g_iommu->init_dom0_mappings();
            g_iommu->enable();
            bfdebug_info(0, "IOMMU init'd");
        });
    }
    else {
        this->setup_domU();
        g_iommu->set_domU_eptp(m_ept_map.eptp());
        g_iommu->init_domU_mappings();
    }
}

void
domain::setup_dom0()
{
    ept::identity_map(m_ept_map, MAX_PHYS_ADDR);
}

void
domain::setup_domU()
{
    using namespace ::x64::access_rights;

    m_gdt_phys = g_mm->virtint_to_physint(m_gdt.base());
    m_idt_phys = g_mm->virtint_to_physint(m_idt.base());
    m_tss_phys = g_mm->virtptr_to_physint(m_tss.get());

    m_gdt_virt = INITIAL_GDT_GPA;
    m_idt_virt = INITIAL_IDT_GPA;
    m_tss_virt = INITIAL_TSS_GPA;

    m_gdt.set(2, nullptr, 0xFFFFFFFF, 0xc09b);
    m_gdt.set(3, nullptr, 0xFFFFFFFF, 0xc093);
    m_gdt.set(4, m_tss_virt, sizeof(m_tss), 0x008b);

    m_ept_map.map_4k(m_tss_virt, m_tss_phys, ept::mmap::attr_type::read_write);
    m_ept_map.map_4k(m_gdt_virt, m_gdt_phys, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(m_idt_virt, m_idt_phys, ept::mmap::attr_type::read_only);

    this->setup_acpi();
}

void
domain::setup_acpi()
{
    std::strncpy(m_rsdp->signature, "RSD PTR ", sizeof(m_rsdp->signature));
    m_rsdp->checksum = 0;
    std::strncpy(m_rsdp->oemid, "AIS", sizeof(m_rsdp->oemid));
    m_rsdp->revision = 2;
    m_rsdp->rsdtphysicaladdress = 0;
    m_rsdp->length = sizeof(rsdp_t);
    m_rsdp->xsdtphysicaladdress = ACPI_XSDT_GPA;
    m_rsdp->extendedchecksum = 0;
    std::memset(m_rsdp->reserved, 0, sizeof(m_rsdp->reserved));
    m_rsdp->checksum = acpi_checksum(m_rsdp.get(), 20);
    m_rsdp->extendedchecksum = acpi_checksum(m_rsdp.get(), m_rsdp->length);

    std::strncpy(m_xsdt->header.signature, "XSDT", sizeof(m_xsdt->header.signature));
    m_xsdt->header.length = sizeof(xsdt_t);
    m_xsdt->header.revision = 1;
    m_xsdt->header.checksum = 0;
    std::strncpy(m_xsdt->header.oemid, OEMID, sizeof(m_xsdt->header.oemid));
    std::strncpy(m_xsdt->header.oemtableid, OEMTABLEID, sizeof(m_xsdt->header.oemtableid));
    m_xsdt->header.oemrevision = OEMREVISION;
    std::strncpy(m_xsdt->header.aslcompilerid, ASLCOMPILERID, sizeof(m_xsdt->header.aslcompilerid));
    m_xsdt->header.aslcompilerrevision = ASLCOMPILERREVISION;
    m_xsdt->entries[0] = ACPI_MADT_GPA;
    m_xsdt->entries[1] = ACPI_FADT_GPA;
    m_xsdt->entries[2] = ACPI_MCFG_GPA;
    m_xsdt->header.checksum = acpi_checksum(m_xsdt.get(), m_xsdt->header.length);

    std::strncpy(m_madt->header.signature, "APIC", sizeof(m_madt->header.signature));
    m_madt->header.length = sizeof(madt_t);
    m_madt->header.revision = 4;
    m_madt->header.checksum = 0;
    std::strncpy(m_madt->header.oemid, OEMID, sizeof(m_madt->header.oemid));
    std::strncpy(m_madt->header.oemtableid, OEMTABLEID, sizeof(m_madt->header.oemtableid));
    m_madt->header.oemrevision = OEMREVISION;
    std::strncpy(m_madt->header.aslcompilerid, ASLCOMPILERID, sizeof(m_madt->header.aslcompilerid));
    m_madt->header.aslcompilerrevision = ASLCOMPILERREVISION;
    m_madt->address = LAPIC_GPA;
    m_madt->flags = 0;
    m_madt->lapic.header.type = ICS_TYPE_LOCAL_APIC;
    m_madt->lapic.header.length = 8;
    m_madt->lapic.processorid = 0;      // TODO: This should be generated from the vCPUs
    m_madt->lapic.id = 0;               // TODO: This should be generated from the vCPUs
    m_madt->lapic.flags = 1;
    m_madt->header.checksum = acpi_checksum(m_madt.get(), m_madt->header.length);

    std::strncpy(m_fadt->header.signature, "FACP", sizeof(m_fadt->header.signature));
    m_fadt->header.length = sizeof(fadt_t);
    m_fadt->header.revision = 6;
    m_fadt->header.checksum = 0;
    std::strncpy(m_fadt->header.oemid, OEMID, sizeof(m_fadt->header.oemid));
    std::strncpy(m_fadt->header.oemtableid, OEMTABLEID, sizeof(m_fadt->header.oemtableid));
    m_fadt->header.oemrevision = OEMREVISION;
    std::strncpy(m_fadt->header.aslcompilerid, ASLCOMPILERID, sizeof(m_fadt->header.aslcompilerid));
    m_fadt->header.aslcompilerrevision = ASLCOMPILERREVISION;
    m_fadt->dsdt = 0;
    m_fadt->flags = 0x101873U;
    m_fadt->minorrevision = 1;
    m_fadt->xdsdt = ACPI_DSDT_GPA;
    m_fadt->hypervisorid = 0xBFU;
    m_fadt->header.checksum = acpi_checksum(m_fadt.get(), m_fadt->header.length);

    std::strncpy(m_dsdt->header.signature, "DSDT", sizeof(m_dsdt->header.signature));
    m_dsdt->header.length = sizeof(dsdt_t);
    m_dsdt->header.revision = 6;
    m_dsdt->header.checksum = 0;
    std::strncpy(m_dsdt->header.oemid, OEMID, sizeof(m_dsdt->header.oemid));
    std::strncpy(m_dsdt->header.oemtableid, OEMTABLEID, sizeof(m_dsdt->header.oemtableid));
    m_dsdt->header.oemrevision = OEMREVISION;
    std::strncpy(m_dsdt->header.aslcompilerid, ASLCOMPILERID, sizeof(m_dsdt->header.aslcompilerid));
    m_dsdt->header.aslcompilerrevision = ASLCOMPILERREVISION;
    m_dsdt->header.checksum = acpi_checksum(m_dsdt.get(), m_dsdt->header.length);

    std::strncpy(m_mcfg->signature, "MCFG", sizeof(m_mcfg->signature));
    m_mcfg->length = sizeof(mcfg_t);
    m_mcfg->revision = 1;
    m_mcfg->csum = 0;
    std::strncpy(m_mcfg->oemid, OEMID, sizeof(m_mcfg->oemid));
    std::strncpy(m_mcfg->oemtableid, OEMTABLEID, sizeof(m_mcfg->oemtableid));
    m_mcfg->oemrevision = OEMREVISION;
    std::strncpy(m_mcfg->creatorid, "AIS", sizeof(4));
    m_mcfg->creatorrevision = 0;

    m_mcfg->entry[0].base = 0xF8000000;
    m_mcfg->entry[0].segment = 0;
    m_mcfg->entry[0].start_bus = 2;
    m_mcfg->entry[0].end_bus = 2;
    m_mcfg->entry[0].rsvd = 0;

    m_mcfg->csum = acpi_checksum(m_mcfg.get(), m_mcfg->length);

    auto rsdp_hpa = g_mm->virtptr_to_physint(m_rsdp.get());
    auto xsdt_hpa = g_mm->virtptr_to_physint(m_xsdt.get());
    auto madt_hpa = g_mm->virtptr_to_physint(m_madt.get());
    auto fadt_hpa = g_mm->virtptr_to_physint(m_fadt.get());
    auto dsdt_hpa = g_mm->virtptr_to_physint(m_dsdt.get());
    auto mcfg_hpa = g_mm->virtptr_to_physint(m_mcfg.get());

    m_ept_map.map_4k(ACPI_RSDP_GPA, rsdp_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_XSDT_GPA, xsdt_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_MADT_GPA, madt_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_FADT_GPA, fadt_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_DSDT_GPA, dsdt_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_MCFG_GPA, mcfg_hpa, ept::mmap::attr_type::read_only);
}

void
domain::map_1g_ro(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_2m_ro(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_4k_ro(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_only); }

void
domain::map_1g_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_2m_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_4k_rw(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_write); }

void
domain::map_4k_rw_uc(uintptr_t gpa, uintptr_t hpa)
{
    m_ept_map.map_4k(gpa,
                     hpa,
                     ept::mmap::attr_type::read_write,
                     ept::mmap::memory_type::uncacheable);
}

void
domain::map_1g_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::map_2m_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::map_4k_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

uintptr_t
domain::unmap(uintptr_t gpa)
{ return m_ept_map.unmap(gpa); }

void
domain::release(uintptr_t gpa)
{ m_ept_map.release(gpa); }

void
domain::add_e820_entry(const e820_entry_t &entry)
{ m_e820_map.emplace_back(entry); }

void
domain::set_uart(uart::port_type uart) noexcept
{ m_uart_port = uart; }

void
domain::set_pt_uart(uart::port_type uart) noexcept
{ m_pt_uart_port = uart; }

void
domain::setup_vcpu_uarts(gsl::not_null<vcpu *> vcpu)
{
    // Note:
    //
    // We explicitly disable the 4 default com ports. This is because the
    // Linux guest will attempt to probe these ports so they need to be
    // handled by something.
    //

    m_uart_3F8.disable(vcpu);
    m_uart_2F8.disable(vcpu);
    m_uart_3E8.disable(vcpu);
    m_uart_2E8.disable(vcpu);

    if (m_pt_uart_port == 0) {
        switch(m_uart_port) {
            case 0x3F8: m_uart_3F8.enable(vcpu); break;
            case 0x2F8: m_uart_2F8.enable(vcpu); break;
            case 0x3E8: m_uart_3E8.enable(vcpu); break;
            case 0x2E8: m_uart_2E8.enable(vcpu); break;

            default:
                break;
        };
    }
    else {
        m_pt_uart = std::make_unique<uart>(m_pt_uart_port);
        m_pt_uart->pass_through(vcpu);
    }
}

uint64_t
domain::dump_uart(const gsl::span<char> &buffer)
{
    if (m_pt_uart) {
        m_pt_uart->dump(buffer);
    }
    else {
        switch(m_uart_port) {
            case 0x3F8: return m_uart_3F8.dump(buffer);
            case 0x2F8: return m_uart_2F8.dump(buffer);
            case 0x3E8: return m_uart_3E8.dump(buffer);
            case 0x2E8: return m_uart_2E8.dump(buffer);

            default:
                break;
        };
    }

    return 0;
}

}
