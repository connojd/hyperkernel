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

#include <array>
#include <mutex>
#include <cstdint>

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

/// Config data common to every visr device. Note that visr only
/// supports "normal" (type-0) devices, so it has 6 BARS, all zero
///
static constexpr uint32_t dev_ven = 0xBEEF'F00D;
static constexpr uint32_t sts_cmd = 0x0010'0402;
static constexpr uint32_t class_sub_prog_rev = 0xFF'00'00'00;
static constexpr uint32_t bist_hdr_ltimer_clsz = 0x00'00'00'10;
static constexpr uint32_t capptr = 0x50;
static constexpr uint32_t msi_base = capptr / sizeof(uint32_t);

/// Normal PCI dev
///
struct EXPORT_HYPERKERNEL_HVE pci_dev
{
    pci_dev(uint32_t bus, uint32_t dev, uint32_t fun) :
        m_cf8{bdf_to_cf8(bus, dev, fun)}
    { }

    uint32_t bus() const { return cf8_to_bus(m_cf8); }
    uint32_t dev() const { return cf8_to_dev(m_cf8); }
    uint32_t fun() const { return cf8_to_fun(m_cf8); }
    uint32_t phys_vec() const { return m_phys_vec; }
    uint32_t virt_vec() const { return m_virt_vec; }
    uint32_t reg(uint32_t reg) const { return m_cfg.at(reg); }
    uint64_t vcpuid() const { return m_vcpuid; }

    void set_reg(uint32_t reg, uint32_t val) { m_cfg.at(reg) = val; }
    void set_phys_vec(uint32_t vec) { m_phys_vec = vec; }
    void set_virt_vec(uint32_t vec) { m_virt_vec = vec; }
    void set_used() { m_used = true; }
    void set_vcpuid(uint64_t id) { m_vcpuid = id; }

    bool is_bar(uint32_t reg) const { return reg >= 4 && reg <= 9; }
    bool is_msi(uint32_t reg) const { return reg >= msi_base && reg <= msi_base + 4; }
    bool is_used() const { return m_used; }

    ~pci_dev() = default;
    pci_dev(pci_dev &&v) = default;
    pci_dev(const pci_dev &v) = delete;
    pci_dev &operator=(pci_dev &&v) = default;
    pci_dev &operator=(const pci_dev &v) = delete;

private:

    uint32_t m_cf8{};
    uint32_t m_phys_vec{};
    uint32_t m_virt_vec{};
    uint64_t m_vcpuid{};
    bool m_used{};
    std::array<uint32_t, 64> m_cfg{};
};

/// VISR
///
/// VISR is a singleton that provides an emulate() function that
/// enables emulation at the provided bus/device/function
///
class EXPORT_HYPERKERNEL_HVE visr
{
public:

    /// Constructor
    ///
    visr() = default;

    /// Destructor
    ///
    ~visr() = default;

    /// Get the visr instance
    ///
    static visr *instance() noexcept;

    /// Enable emulation (installs the exit handlers on the given vcpu)
    ///
    void enable(gsl::not_null<vcpu *> vcpu);

    /// Add a device to emulate
    ///
    void add_dev(uint32_t bus, uint32_t dev, uint32_t fun);

    /// Save the physical vector for subsequent allocation
    ///
    void stash_phys_vector(uint32_t vec);

    /// Deliver interrupt to the given vcpu
    ///
    bool deliver(vcpu *vcpu, uint32_t vec);

    /// Retrieve a physical vector for NDVM usage
    ///
    /// @param vcpuid the id of the vcpu acquiring the vector
    /// @return a physical vector available to the vcpu
    ///
    uint32_t get_phys_vector(uint64_t vcpuid);

    /// Map the virtual vector to the given vcpu. This is the last
    /// step required before the physical interrupt can be injected
    /// by visr
    ///
    /// @param vcpuid the id of the vcpu acquiring the vector
    /// @param vec the vector the guest vcpu is expecting
    ///
    void set_virt_vector(uint64_t vcpuid, uint32_t vec);

    /// Is visr emulating the device @cf8?
    ///
    bool is_emulating(uint32_t cf8) const;

    /// CPUID/virtual interrupt handlers
    ///
    bool receive_vector_from_windows(gsl::not_null<vcpu_t *> vcpu, cpuid_handler::info_t &info);
    bool forward_interrupt_to_ndvm(gsl::not_null<vcpu_t *> vcpu, cpuid_handler::info_t &info);

    /// Port IO handlers
    ///
    bool handle_cfc_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfd_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfe_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cff_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfc_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfd_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cfe_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);
    bool handle_cff_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info);

private:

    std::mutex m_mutex;
    std::unordered_map<uint32_t, struct pci_dev> m_pci_devs{};

public:

    /// @cond

    visr(visr &&) noexcept = delete;
    visr &operator=(visr &&) noexcept = delete;
    visr(const visr &) = delete;
    visr &operator=(const visr &) = delete;

    /// @endcond
};
}

/// visr macro
///
/// The following macro can be used to quickly call for visr services
///
/// @expects
/// @ensures g_visr != nullptr
///
#define g_visr hyperkernel::intel_x64::visr::instance()

#endif
