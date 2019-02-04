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

#ifndef IOAPIC_INTEL_X64_HYPERKERNEL_H
#define IOAPIC_INTEL_X64_HYPERKERNEL_H

#include <bfgpalayout.h>

#include <eapis/hve/arch/intel_x64/ioapic.h>
#include <bfvmm/memory_manager/memory_manager.h>

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

class EXPORT_HYPERKERNEL_HVE ioapic
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu associated with this ioapic
    ///
    /// @cond
    ///
    explicit ioapic(gsl::not_null<vcpu *> vcpu);

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~ioapic() = default;

    /// Initialize
    ///
    /// We have to initialize later on during the construction process to give
    /// EPT time to set up, so this function must be called manually after
    /// EPTP has been set. This will initialize the IOAPIC and get it
    /// ready to access guest reads and writes
    ///
    /// @expects
    /// @ensures
    ///
    void init();

    /// IOAPIC ID
    ///
    /// The APIC ID and the vCPU ID do not need to agree, and on some systems
    /// they don't. This provides that level of flexibility by returning the
    /// APIC's ID
    ///
    /// TODO:
    ///
    /// Note that each domain will have to generate APIC IDs for us so that
    /// the APIC IDs start from 0 on each VM. For now this returns 0 as we
    /// don't support more than on vCPU. Once we attempt to add more than one
    /// vCPU, we will need to implement this. Note also that ACPI and the
    /// MP tables will have to be updated
    ///
    /// @return IOAPIC ID
    ///
    uint32_t id();

    /// Base address
    ///
    /// This function returns the base address for this IOAPIC as a GPA.
    /// The HPA is maintained internally to this class and is not accessible.
    ///
    /// @return IOAPIC base GPA
    ///
    uint32_t base() const;

    /// Select
    ///
    /// Select a register to access
    ///
    /// @param offset the offset to access
    ///
    void select(uint32_t offset);

    /// Read
    ///
    /// Read the value from the previously select()'d  register
    ///
    uint32_t read() const;

    /// Write
    ///
    /// Write the value to a register
    ///
    /// @param val the value to write to the previously
    ///        select()'d register
    ///
    void write(uint32_t val);

    /// Set window
    ///
    /// Write a value to IOWIN
    ///
    /// @param val the value to write to the window
    ///
    void set_window(uint32_t val);

private:

    vcpu *m_vcpu;
    page_ptr<uint32_t> m_ioapic_page;
    gsl::span<uint32_t> m_ioapic_view;
    uint64_t m_offset{};
};
}

#endif
