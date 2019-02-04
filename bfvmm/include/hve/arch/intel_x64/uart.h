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

#ifndef UART_INTEL_X64_HYPERKERNEL_H
#define UART_INTEL_X64_HYPERKERNEL_H

#include <bfgsl.h>
#include <bftypes.h>
#include <bfhypercall.h>

#include <array>
#include <mutex>

#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <eapis/hve/arch/intel_x64/vmexit/cpuid.h>
#include <eapis/hve/arch/intel_x64/vmexit/io_instruction.h>

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

class EXPORT_HYPERKERNEL_HVE uart
{
public:

    using port_type = uint16_t;
    using data_type = uint8_t;

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu associated with this uart
    ///
    /// @cond
    ///
    explicit uart(port_type port);

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~uart() = default;

    /// Enable
    ///
    /// Enables the emulation of the UART. When this is enabled, the UART
    /// becomes active, presenting itself as present and capable of recording
    /// string data.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu to enable this UART on
    ///
    void enable(gsl::not_null<vcpu *> vcpu);

    /// Disable
    ///
    /// Disables the UART. All reads to this UART from the guest will result
    /// in zero while all writes to this UART will be ignored.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu to disable this UART on
    ///
    void disable(gsl::not_null<vcpu *> vcpu);

    /// Pass-Through
    ///
    /// Instead of emulating the UART, this will cause the UART to be passed
    /// through to the guest, physically giving the guest the device. Special
    /// care should be used when enabling this feature as the guest will own
    /// the device and be externally accessible.
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu to pass-through this UART on
    ///
    void pass_through(gsl::not_null<vcpu *> vcpu);

    /// Dump
    ///
    /// Dumps the contents of the UARTs buffer into a gsl::span so that it
    /// can be given to an app that is providing the UART buffer to the
    /// user.
    ///
    /// @param buffer the buffer to dump the contents of the UART into
    /// @return the number of bytes transferred to the buffer
    ///
    uint64_t dump(const gsl::span<char> &buffer);

private:

    bool io_zero_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool io_ignore_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);

    bool reg0_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg1_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg2_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg3_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg4_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg5_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg6_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg7_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);

    bool reg0_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg1_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg2_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg3_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg4_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg5_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg6_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);
    bool reg7_out_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::io_instruction_handler::info_t &info);

    bool cpuid_in_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);

    bool dlab() const
    { return m_line_control_register & 0x80; }

    void write(const char c);
    void write(const char *str);

private:

    port_type m_port{};

    std::mutex m_mutex{};
    std::size_t m_index{};
    std::array<char, UART_MAX_BUFFER> m_buffer{};

    data_type m_baud_rate_l{};
    data_type m_baud_rate_h{};
    data_type m_line_control_register{};

};

}

#endif
