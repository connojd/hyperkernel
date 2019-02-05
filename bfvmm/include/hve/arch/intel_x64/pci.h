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

#ifndef PCI_INTEL_X64_HYPERKERNEL_H
#define PCI_INTEL_X64_HYPERKERNEL_H

#include <stdint.h>
#include <array>
#include <list>
#include <intrinsics.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

namespace hyperkernel::intel_x64
{

#define NIC_BUS 0x2
#define NIC_DEV 0x0
#define NIC_FUN 0x0

using namespace ::x64::portio;
using namespace eapis::intel_x64;
namespace io = vmcs_n::exit_qualification::io_instruction;

inline bool cf8_is_enabled(uint32_t cf8)
{ return ((cf8 & 0x80000000UL) >> 31) != 0; }

inline uint32_t cf8_to_bus(uint32_t cf8)
{ return (cf8 & 0x00FF0000UL) >> 16; }

inline uint32_t cf8_to_dev(uint32_t cf8)
{ return (cf8 & 0x0000F800UL) >> 11; }

inline uint32_t cf8_to_fun(uint32_t cf8)
{ return (cf8 & 0x00000700UL) >> 8; }

inline uint32_t cf8_to_reg(uint32_t cf8)
{ return (cf8 & 0x000000FCUL) >> 2; }

inline uint32_t cf8_to_off(uint32_t cf8)
{ return (cf8 & 0x00000003UL); }

//TODO: save the existing CF8 so we don't clobber the host
inline uint32_t cf8_read_reg(uint32_t cf8, uint32_t reg)
{
    const auto addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    outd(0xCF8, addr);
    return ind(0xCFC);
}

inline void cf8_write_reg(uint32_t cf8, uint32_t reg, uint32_t val)
{
    const auto addr = (cf8 & 0xFFFFFF03UL) | (reg << 2);
    outd(0xCF8, addr);
    outd(0xCFC, val);
}

inline uint32_t bdf_to_cf8(uint32_t b, uint32_t d, uint32_t f)
{
    return (1UL << 31) | (b << 16) | (d << 11) | (f << 8);
}

inline bool domU_owned_cf8(uint32_t cf8)
{
    return cf8_to_bus(cf8) == NIC_BUS &&
           cf8_to_dev(cf8) == NIC_DEV &&
           cf8_to_fun(cf8) == NIC_FUN;
}

inline bool cf8_exists(uint32_t cf8)
{ return cf8_read_reg(cf8, 0) != 0xFFFFFFFF; }

enum pci_header_t {
    pci_hdr_normal               = 0x00,
    pci_hdr_pci_bridge           = 0x01,
    pci_hdr_cardbus_bridge       = 0x02,
    pci_hdr_normal_multi         = 0x80 | pci_hdr_normal,
    pci_hdr_pci_bridge_multi     = 0x80 | pci_hdr_pci_bridge,
    pci_hdr_cardbus_bridge_multi = 0x80 | pci_hdr_cardbus_bridge,
    pci_hdr_nonexistant          = 0xFF
};

enum pci_class_code_t {
    pci_cc_unclass = 0x00,
    pci_cc_storage = 0x01,
    pci_cc_network = 0x02,
    pci_cc_display = 0x03,
    pci_cc_multimedia = 0x04,
    pci_cc_memory = 0x05,
    pci_cc_bridge = 0x06,
    pci_cc_simple_comms = 0x07,
    pci_cc_input = 0x09,
    pci_cc_processor = 0x0B,
    pci_cc_serial_bus = 0x0C,
    pci_cc_wireless = 0x0D
};

enum pci_subclass_bridge_t {
    pci_sc_bridge_host = 0x00,
    pci_sc_bridge_isa = 0x01,
    pci_sc_bridge_eisa = 0x02,
    pci_sc_bridge_mca = 0x03,
    pci_sc_bridge_pci_decode = 0x04,
    pci_sc_bridge_pcmcia = 0x05,
    pci_sc_bridge_nubus = 0x06,
    pci_sc_bridge_cardbus = 0x07,
    pci_sc_bridge_raceway = 0x08,
    pci_sc_bridge_pci_semi_trans = 0x09,
    pci_sc_bridge_infiniband = 0x0A,
    pci_sc_bridge_other = 0x80
};

inline uint32_t pci_header_type(uint32_t cf8)
{
    const auto val = cf8_read_reg(cf8, 3);
    return (val & 0x00FF0000UL) >> 16;
}

inline uint32_t pci_phys_read(uint32_t addr, uint32_t port, uint32_t size)
{
    expects(port >= 0xCFC && port <= 0xCFF);
    outd(0xCF8, addr);

    switch (size) {
        case io::size_of_access::one_byte:  return inb(port);
        case io::size_of_access::two_byte:  return inw(port);
        case io::size_of_access::four_byte: return ind(port);
        default: throw std::runtime_error("Invalid PCI access size");
    }
}

inline void pci_info_in(uint32_t cf8, io_instruction_handler::info_t &info)
{ info.val = pci_phys_read(cf8, info.port_number, info.size_of_access); }

inline bool is_host_bridge(uint32_t cf8)
{
    const auto val = cf8_read_reg(cf8, 2);
    const auto cc = (val & 0xFF000000UL) >> 24;
    const auto sc = (val & 0x00FF0000UL) >> 16;

    return cc == pci_cc_bridge && sc == pci_sc_bridge_host;
}

inline void bferror_dump_cf8(int level, uint32_t cf8)
{
    bferror_subbool(level, "enabled", cf8_is_enabled(cf8));
    bferror_subnhex(level, "bus", cf8_to_bus(cf8));
    bferror_subnhex(level, "dev", cf8_to_dev(cf8));
    bferror_subnhex(level, "fun", cf8_to_fun(cf8));
    bferror_subnhex(level, "reg", cf8_to_reg(cf8));
    bferror_subnhex(level, "off", cf8_to_off(cf8));
}

using probe_t = delegate<void(uint32_t)>;

inline void probe_bus(uint32_t b, probe_t probe)
{
    for (auto d = 0; d < 32; d++) {
        for (auto f = 0; f < 8; f++) {
            auto cf8 = bdf_to_cf8(b, d, f);
            if (cf8_read_reg(cf8, 0) == 0xFFFFFFFF) {
                continue;
            }

            // Call the probe callback for each valid device/vendor
            probe(cf8);

            switch (pci_header_type(cf8)) {
            case pci_hdr_pci_bridge:
            case pci_hdr_pci_bridge_multi: {
                auto child = (cf8_read_reg(cf8, 0x6) & 0xFF00) >> 8;
                probe_bus(child, probe);
                }
                break;
            default:
                break;
            }
        }
    }
}

inline void debug_pci_in(uint32_t cf8, io_instruction_handler::info_t &info)
{
    const char *port = "";

    switch (info.port_number) {
        case 0xCFC: port = "CFC"; break;
        case 0xCFD: port = "CFD"; break;
        case 0xCFE: port = "CFE"; break;
        case 0xCFF: port = "CFF"; break;
        default:
            bferror_nhex(0, "Invalid PCI in port:", info.port_number);
            throw std::runtime_error("Invalid PCI in port");
    }

    switch (pci_header_type(cf8)) {
        case pci_hdr_nonexistant:
            break;

        case pci_hdr_normal:
        case pci_hdr_normal_multi:
        case pci_hdr_pci_bridge:
        case pci_hdr_pci_bridge_multi:
            printf("%s in : %02x:%02x:%02x:%02x:%02x, size: %lu, ",
                port, cf8_to_bus(cf8),
                cf8_to_dev(cf8), cf8_to_fun(cf8),
                cf8_to_reg(cf8), cf8_to_off(cf8),
                info.size_of_access + 1);
            break;
    }
}

inline void debug_pci_out(uint32_t cf8, io_instruction_handler::info_t &info)
{
    const char *port = "";

    switch (info.port_number) {
        case 0xCFC: port = "CFC"; break;
        case 0xCFD: port = "CFD"; break;
        case 0xCFE: port = "CFE"; break;
        case 0xCFF: port = "CFF"; break;
        default:
            bferror_nhex(0, "Invalid PCI out port:", info.port_number);
            throw std::runtime_error("Invalid PCI out port");
    }

    switch (pci_header_type(cf8)) {
        case pci_hdr_nonexistant:
            break;

        case pci_hdr_normal:
        case pci_hdr_normal_multi:
        case pci_hdr_pci_bridge:
        case pci_hdr_pci_bridge_multi:
            printf("%s out: %02x:%02x:%02x:%02x:%02x, size: %lu, ",
                port, cf8_to_bus(cf8),
                cf8_to_dev(cf8), cf8_to_fun(cf8),
                cf8_to_reg(cf8), cf8_to_off(cf8),
                info.size_of_access + 1);
            break;

        default:
            bferror_nhex(0, "Unhandled PCI header:", pci_header_type(cf8));
            bferror_nhex(0, "m_cf8:", cf8);
            bferror_dump_cf8(0, cf8);
            bferror_lnbr(0); {
                const auto cur = ind(0xCF8);
                bferror_nhex(0, "0xCF8:", cur);
                bferror_dump_cf8(0, cur);
                bferror_lnbr(0);
            }
            bferror_nhex(0, "0xCFC:", ind(0xCFC));
            throw std::runtime_error("Unhandled PCI header");
    }
}

inline void pci_phys_write(uint32_t addr,
                    uint32_t port,
                    uint32_t size,
                    uint32_t data)
{
    expects(port >= 0xCFC && port <= 0xCFF);
    outd(0xCF8, addr);

    switch (size) {
    case io::size_of_access::one_byte:
        outb(port, gsl::narrow_cast<uint8_t>(data));
        break;
    case io::size_of_access::two_byte:
        outw(port, gsl::narrow_cast<uint16_t>(data));
        break;
    case io::size_of_access::four_byte:
        outd(port, gsl::narrow_cast<uint32_t>(data));
        break;
    default:
        throw std::runtime_error("Invalid PCI access size");
    }
}

inline void
pci_info_out(uint32_t cf8, const io_instruction_handler::info_t &info)
{
    pci_phys_write(cf8,
                   info.port_number,
                   info.size_of_access,
                   info.val);
}

enum pci_bar_t {
    pci_bar_mm,
    pci_bar_io
};

struct pci_bar {
    uint8_t bar_type;
    uint8_t mm_type;
    uintptr_t addr;
    uint32_t size;
    bool prefetchable;
};

using pci_bars_t = std::list<struct pci_bar>;

inline void parse_bar_size(
    uint32_t cf8,
    uint32_t reg,
    uint32_t val,
    uint32_t mask,
    uint32_t *size)
{
    cf8_write_reg(cf8, reg, 0xFFFFFFFF);

    auto len = cf8_read_reg(cf8, reg);
    len = ~(len & mask) + 1U;
    *size = len;

    cf8_write_reg(cf8, reg, val);
}

inline void parse_bars_normal(uint32_t cf8, pci_bars_t &bars)
{
    const std::array<uint8_t, 6> bar_regs = {0x4, 0x5, 0x6, 0x7, 0x8, 0x9};

    for (auto i = 0; i < bar_regs.size(); i++) {
        const auto reg = bar_regs[i];
        const auto val = cf8_read_reg(cf8, reg);

        if (val == 0) {
            continue;
        }

        struct pci_bar bar{};

        if ((val & 0x1) != 0) { // IO bar
            parse_bar_size(cf8, reg, val, 0xFFFFFFFC, &bar.size);
            bar.addr = val & 0xFFFFFFFC;
            bar.bar_type = pci_bar_io;
        } else {                // MM bar
            parse_bar_size(cf8, reg, val, 0xFFFFFFF0, &bar.size);
            bar.addr = (val & 0xFFFFFFF0);
            bar.prefetchable = (val & 0x8) != 0;
            bar.mm_type = (val & 0x6) >> 1;

            if (bar.mm_type == 2) {
                bar.addr |= gsl::narrow_cast<uintptr_t>(cf8_read_reg(cf8, bar_regs.at(++i))) << 32;
            }
            bar.bar_type = pci_bar_mm;
        }

        bars.push_back(bar);
    }
}

inline void parse_bars_pci_bridge(uint32_t cf8, pci_bars_t &bars)
{
    const std::array<uint8_t, 2> bar_regs = {0x4, 0x5};

    for (auto i = 0; i < bar_regs.size(); i++) {
        const auto reg = bar_regs[i];
        const auto val = cf8_read_reg(cf8, reg);

        if (val == 0) {
            continue;
        }

        struct pci_bar bar{};

        if ((val & 0x1) != 0) { // IO bar
            parse_bar_size(cf8, reg, val, 0xFFFFFFFC, &bar.size);
            bar.addr = val & 0xFFFFFFFC;
            bar.bar_type = pci_bar_io;
        } else {                // MM bar
            parse_bar_size(cf8, reg, val, 0xFFFFFFF0, &bar.size);
            bar.addr = (val & 0xFFFFFFF0);
            bar.prefetchable = (val & 0x8) != 0;
            bar.mm_type = (val & 0x6) >> 1;

            if (bar.mm_type == 2) {
                bar.addr |= gsl::narrow_cast<uintptr_t>(cf8_read_reg(cf8, bar_regs.at(++i))) << 32;
            }
            bar.bar_type = pci_bar_mm;
        }

        bars.push_back(bar);
    }
}

inline void pci_parse_bars(uint32_t cf8, pci_bars_t &bars)
{
    const auto hdr = pci_header_type(cf8);

    switch (hdr) {
    case pci_hdr_normal:
    case pci_hdr_normal_multi:
        parse_bars_normal(cf8, bars);
        return;

    case pci_hdr_pci_bridge:
    case pci_hdr_pci_bridge_multi:
        parse_bars_pci_bridge(cf8, bars);
        return;

    default:
        bfalert_nhex(0, "Unsupported header type for PCI bar parsing", hdr);
        return;
    }
}

}

#endif
