//
// Bareflank Hyperkernel
// Copyright (C) 2015 Assured Information Security, Inc.
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

#ifndef PCI_X64_H
#define PCI_X64_H

#include <cstdio>
#include <arch/x64/portio.h>

namespace x64::pci
{

using namespace ::x64::portio;
using addr_t = uint32_t;

enum header_t { standard, pci_bridge, cardbus_bridge };

inline void dump_addr(addr_t cf8)
{
    printf("bus: %02x, dev: %02x, fun: %02x, reg: %02x, off: %02x\n",
        (cf8 & 0xFF0000) >> 16,
        (cf8 & 0xF800) >> 11,
        (cf8 & 0x700) >> 8,
        (cf8 & 0xFC) >> 2,
        (cf8 & 0x3)
    );
}

inline auto reg(addr_t cf8)
{ return (cf8 & 0xFCUL) >> 2; }

inline auto set_reg(addr_t cf8, addr_t reg)
{
    cf8 &= ~0xFFUL;
    cf8 |= (reg << 2);

    return cf8;
}

inline auto header_type(addr_t cf8)
{
    set_reg(cf8, 3);
    outd(0xCF8, cf8);

    return (ind(0xCFC) & 0xFF0000) >> 16;
}

// For now, we only passthrough what Linux requires:
//
// host, isa, pci
//
inline auto valid_bridge(addr_t cf8)
{
    set_reg(cf8, 3);
    outd(0xCF8, cf8);

    auto reg = ind(0xCFC);
    auto cc = (reg & 0xFF000000) >> 24;
    auto sc = (reg & 0x00FF0000) >> 16;

    return cc == 0x6 && (sc == 0 || sc == 1 || sc == 4 || sc == 9);
}

}

#endif
