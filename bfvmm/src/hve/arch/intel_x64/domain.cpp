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
#include <eapis/hve/arch/intel_x64/ioapic.h>

#include "../../../../../include/gpa_layout.h"

using namespace eapis::intel_x64;

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

domain::domain(domainid_type domainid) :
    hyperkernel::domain{domainid},
    m_tss{make_page<bfvmm::x64::tss>()},
    m_rsdp{make_page<rsdp_t>()},
    m_xsdt{make_page<xsdt_t>()},
    m_madt{make_page<madt_t>()},
    m_fadt{make_page<fadt_t>()},
    m_dsdt{make_page<dsdt_t>()},
    m_mpfp{make_page<x64::mpfp_t>()}
{
    if (domainid == 0) {
        this->setup_dom0();
    }
    else {
        this->setup_domU();
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
    m_tss_phys = g_mm->virtptr_to_physint(m_tss.get());

    m_gdt_virt = 0x1000;
    m_idt_virt = 0x2000;
    m_tss_virt = 0x3000;

    m_gdt.set(2, nullptr, 0xFFFFFFFF, 0xc09b);
    m_gdt.set(3, nullptr, 0xFFFFFFFF, 0xc093);
    m_gdt.set(4, m_tss_virt, sizeof(m_tss), 0x008b);

    m_ept_map.map_4k(m_tss_virt, m_tss_phys, ept::mmap::attr_type::read_write);
    m_ept_map.map_4k(m_gdt_virt, m_gdt_phys, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(m_idt_virt, m_idt_phys, ept::mmap::attr_type::read_only);

    this->setup_acpi();
    this->setup_nic();
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

    m_madt->ioapic.header.type = ICS_TYPE_IO_APIC;
    m_madt->ioapic.header.length = sizeof(ics_ioapic_t);
    m_madt->ioapic.id = 0;
    m_madt->ioapic.reserved = 0;
    m_madt->ioapic.address = IOAPIC_GPA;
    m_madt->ioapic.gsi_base = 0;

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

    /* MP table */
    /* TODO: checksums */

    using namespace ::x64;

    std::strncpy((char *)m_mpfp->signature, "_MP_", 4);
    m_mpfp->address = MP_FLTPTR_GPA + sizeof(mpfp_t);
    m_mpfp->length = 1; /* length in 16-byte units */
    m_mpfp->spec_rev = 4;
    m_mpfp->checksum = 0;
    m_mpfp->feature1 = 0;
    m_mpfp->checksum = acpi_checksum(&m_mpfp->signature, m_mpfp->length * 16);

    auto mpt = reinterpret_cast<mp_table_t *>(&m_mpfp.get()[1]);
    std::strncpy((char *)mpt->hdr.signature, "PCMP", 4);
    mpt->hdr.base_length = sizeof(mp_table_t);
    mpt->hdr.spec_rev = 4;
    mpt->hdr.checksum = 0;
    std::strncpy((char *)mpt->hdr.oem_id, "AIS     ", 8);
    std::strncpy((char *)mpt->hdr.prod_id, "Bareflank   ", 12);
    mpt->hdr.oem_table_ptr = 0;
    mpt->hdr.oem_table_size = 0;
    mpt->hdr.entry_count = 5; /* 1 processor, 2 buses, 1 ioapic, 1 io interrupt */
    mpt->hdr.lapic_address = LAPIC_GPA;
    mpt->hdr.ext_table_length = 0;
    mpt->hdr.ext_table_checksum = 0;
    mpt->hdr.checksum = acpi_checksum(mpt, sizeof(mp_table_t));

    auto cpu = &mpt->cpu;
    cpu->type = mpe_processor;
    cpu->lapic_id = 0; /* TODO get from vcpu */
    cpu->lapic_version = eapis::intel_x64::lapic::version::integrated_apic;
    cpu->cpu_flags = mpe_cpu_en | mpe_cpu_bsp;
    cpu->cpu_signature = 0; /* leave this blank for now */
    cpu->feature_flags = 301; /* fpu, cx8, apic */

    auto root_bus = &mpt->root_bus;
    root_bus->type = mpe_bus;
    root_bus->id = 0;
    strncpy((char *)root_bus->type_str, "PCI   ", 6);

#ifdef NDVM_NIC_BUS
    auto nic_bus = &mpt->nic_bus;
    nic_bus->type = mpe_bus;
    nic_bus->id = NDVM_NIC_BUS;
    strncpy((char *)nic_bus->type_str, "PCI   ", 6);
#else
    #error "NDVM_NIC_BUS not defined"
#endif

#ifdef NDVM_IOAPIC_ID
    //TODO: adjust GSI base from ACPI
    auto ioapic = &mpt->ioapic;
    ioapic->type = mpe_ioapic;
    ioapic->id = NDVM_IOAPIC_ID;
    ioapic->version = eapis::intel_x64::ioapic::version::reset_val & 0xFF;
    ioapic->flags = mpe_ioapic_en;
    ioapic->address = IOAPIC_GPA;
#else
    #error "NDVM_IOAPIC_ID not defined"
#endif

#ifdef NDVM_NIC_PIN
    auto intr = &mpt->io_interrupt;
    intr->type = mpe_io_interrupt;
    intr->interrupt_type = mpi_vectored;
    intr->interrupt_flag = 0; /* conforming trigger and polarity */
    intr->src_bus_id = NDVM_NIC_BUS;
    intr->src_bus_irq = (NDVM_NIC_DEV << 2) | NDVM_NIC_PIN;
    intr->dst_ioapic_id = NDVM_IOAPIC_ID;
#ifdef NDVM_NIC_INTIN
    intr->dst_ioapic_in = NDVM_NIC_INTIN;
#else
    #error "NDVM_NIC_INTIN not defined"
#endif
#else
    #error "NDVM_NIC_PIN not defined"
#endif

    auto rsdp_hpa = g_mm->virtptr_to_physint(m_rsdp.get());
    auto xsdt_hpa = g_mm->virtptr_to_physint(m_xsdt.get());
    auto madt_hpa = g_mm->virtptr_to_physint(m_madt.get());
    auto fadt_hpa = g_mm->virtptr_to_physint(m_fadt.get());
    auto dsdt_hpa = g_mm->virtptr_to_physint(m_dsdt.get());
    auto mpfp_hpa = g_mm->virtptr_to_physint(m_mpfp.get());

    m_ept_map.map_4k(ACPI_RSDP_GPA, rsdp_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_XSDT_GPA, xsdt_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_MADT_GPA, madt_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_FADT_GPA, fadt_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(ACPI_DSDT_GPA, dsdt_hpa, ept::mmap::attr_type::read_only);
    m_ept_map.map_4k(MP_FLTPTR_GPA, mpfp_hpa, ept::mmap::attr_type::read_only);
}

void
domain::setup_nic()
{
    // Non-prefetchable 4K region
    m_ept_map.map_4k(0xF7000000, 0xF7000000, ept::mmap::attr_type::read_write, ept::mmap::memory_type::uncacheable);

    // Prefetchable 16K region
    m_ept_map.map_4k(0xF0000000, 0xF0000000, ept::mmap::attr_type::read_write);
    m_ept_map.map_4k(0xF0001000, 0xF0001000, ept::mmap::attr_type::read_write);
    m_ept_map.map_4k(0xF0002000, 0xF0002000, ept::mmap::attr_type::read_write);
    m_ept_map.map_4k(0xF0003000, 0xF0003000, ept::mmap::attr_type::read_write);
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
domain::map_1g_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_1g(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::map_2m_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_2m(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::map_4k_rwe(uintptr_t gpa, uintptr_t hpa)
{ m_ept_map.map_4k(gpa, hpa, ept::mmap::attr_type::read_write_execute); }

void
domain::unmap(uintptr_t gpa)
{ m_ept_map.unmap(gpa); }

void
domain::release(uintptr_t gpa)
{ m_ept_map.release(gpa); }

void
domain::add_e820_entry(const e820_entry_t &entry)
{ m_e820_map.emplace_back(entry); }

}
