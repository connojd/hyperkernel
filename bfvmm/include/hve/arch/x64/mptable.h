//
// Bareflank Hyperkernel
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

#ifndef MPTABLE_X64_H
#define MPTABLE_X64_H

#include <cstdint>
#include <cstring>

namespace x64
{

/**
 * mpfp_t
 *
 * The MP floating pointer structure contains the physical address of
 * the MP configuration table, in addition to various feature bits.
 *
 */
typedef struct {
    uint8_t signature[4]; /* _MP_ */
    uint32_t address;     /* Physical address of the MP config table */
    uint8_t length;       /* Length in paragraph (16-byte) units */
    uint8_t spec_rev;
    uint8_t checksum;
    uint8_t feature1;     /* 0 -> MP table, != 0 -> default config used */
    uint8_t feature2;     /* Bit 7 -> IMCR is present and PIC is implemented */
    uint8_t feature3;
    uint8_t feature4;
    uint8_t feature5;
} __attribute__((packed)) mpfp_t;

/**
 * struct mpt_header
 *
 * The MP configuration table, as well as various feature information.
 *
 */
typedef struct {
    uint8_t signature[4]; /* PCMP */
    uint16_t base_length;
    uint8_t spec_rev;
    uint8_t checksum;
    uint8_t oem_id[8];
    uint8_t prod_id[12];
    uint32_t oem_table_ptr;
    uint16_t oem_table_size;
    uint16_t entry_count;
    uint32_t lapic_address;
    uint16_t ext_table_length;
    uint8_t ext_table_checksum;
    uint8_t reserved;
} __attribute__((packed)) mp_header_t;

/**
 * MP table entries
 */

enum mpe_type {
    mpe_processor,
    mpe_bus,
    mpe_ioapic,
    mpe_io_interrupt,
    mpe_local_interrupt
};

enum mpi_type {
    mpi_vectored,
    mpi_nmi,
    mpi_smi,
    mpi_extint
};

typedef struct {
    uint8_t type;
    uint8_t lapic_id;
    uint8_t lapic_version;
    uint8_t cpu_flags;
    uint32_t cpu_signature;
    uint32_t feature_flags;
    uint32_t reserved0;
    uint32_t reserved1;
} __attribute__((packed)) mpe_processor_t;

constexpr const auto mpe_cpu_en = 1;
constexpr const auto mpe_cpu_bsp = 2;

typedef struct {
    uint8_t type;
    uint8_t id;
    uint8_t type_str[6];
} __attribute__((packed)) mpe_bus_t;

typedef struct {
    uint8_t type;
    uint8_t id;
    uint8_t version;
    uint8_t flags;
    uint32_t address;
} __attribute__((packed)) mpe_ioapic_t;

constexpr const auto mpe_ioapic_en = 1;

typedef struct {
    uint8_t type;
    uint8_t interrupt_type;
    uint8_t interrupt_flag;
    uint8_t src_bus_id;
    uint8_t src_bus_irq;
    uint8_t dst_ioapic_id;
    uint8_t dst_ioapic_in;
} __attribute__((packed)) mpe_io_interrupt_t;

typedef struct {
    uint8_t type;
    uint8_t interrupt_type;
    uint8_t interrupt_flag;
    uint8_t src_bus_id;
    uint8_t src_bus_irq;
    uint8_t dst_lapic_id;
    uint8_t dst_lapic_in;
} __attribute__((packed)) mpe_local_interrupt_t;

typedef struct {
    mp_header_t hdr;
    mpe_processor_t cpu;
    mpe_bus_t root_bus;
    mpe_bus_t nic_bus;
    mpe_ioapic_t ioapic;
    mpe_io_interrupt_t io_interrupt;
} __attribute__((packed)) mp_table_t;

}

#endif
