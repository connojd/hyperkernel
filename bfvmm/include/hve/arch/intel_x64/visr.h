//
// Bareflank Hyperkernel
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

#ifndef VISR_INTEL_X64_HYPERKERNEL_H
#define VISR_INTEL_X64_HYPERKERNEL_H

#include <cstdint>
#include <array>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HYPERKERNEL_HVE
#ifdef SHARED_HYPERKERNEL_HVE
#define EXPORT_HYPERKERNEL_HVE EXPORT_SYM
#else
#define EXPORT_HYPERKERNEL_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HYPERKERNEL_HVE
#endif

//------------------------------------------------------------------------------
// Definition
//------------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class vcpu;

class EXPORT_HYPERKERNEL_HVE visr
{
public:

    explicit visr(gsl::not_null<vcpu *> vcpu, uint32_t bus, uint32_t dev, uint32_t fun);

    bool handle_cfc_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfd_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfe_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cff_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);

    bool handle_cfc_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfd_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfe_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cff_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);

    bool receive_vector_from_windows(gsl::not_null<vcpu_t *> vcpu, cpuid_handler::info_t &info);
    bool forward_interrupt_to_ndvm(gsl::not_null<vcpu_t *> vcpu, cpuid_handler::info_t &info);

    uint32_t bus() const { return cf8_to_bus(m_self); }
    uint32_t dev() const { return cf8_to_dev(m_self); }
    uint32_t fun() const { return cf8_to_fun(m_self); }

    bool bar(uint32_t reg) const { return reg >= 4 && reg <= 9; }
    bool msi(uint32_t reg) const { return reg >= msi_base && reg <= msi_base + 4; }

    bool self(uint32_t cf8) const
    {
        return cf8_to_bus(cf8) == bus() &&
               cf8_to_dev(cf8) == dev() &&
               cf8_to_fun(cf8) == fun();
    }

    /// Config data common to every visr. Note that visr only supports
    /// "normal" (type-0) devices, so it has 6 BARS, all zero
    ///
    static constexpr uint32_t dev_ven = 0xBEEF'F00D;
    static constexpr uint32_t sts_cmd = 0x0010'0402;
    static constexpr uint32_t class_sub_prog_rev = 0xFF'00'00'00;
    static constexpr uint32_t bist_hdr_ltimer_clsz = 0x00'00'00'10;
    static constexpr uint32_t capptr = 0x50;

    /// Register offset of the MSI capability registers
    static constexpr uint32_t msi_base = capptr / sizeof(uint32_t);

private:

    uint32_t m_self;
    uint32_t m_next;

    std::array<uint32_t, 64> m_cfg{};
    vcpu *m_vcpu{};

public:

    /// @cond

    visr() = default;
    ~visr() = default;
    visr(visr &&) noexcept = default;
    visr &operator=(visr &&) noexcept = default;
    visr(const visr &) = delete;
    visr &operator=(const visr &) = delete;

    /// @endcond
};
}

#endif
