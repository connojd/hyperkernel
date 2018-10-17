//
// Bareflank Hypervisor
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

#ifndef VMEXIT_EXTERNAL_INTERRUPT_INTEL_X64_HYPERKERNEL_H
#define VMEXIT_EXTERNAL_INTERRUPT_INTEL_X64_HYPERKERNEL_H

#include "../base.h"
#include <eapis/hve/arch/intel_x64/vmexit/external_interrupt.h>

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

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class vcpu;

class EXPORT_HYPERKERNEL_HVE external_interrupt_handler
{
public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu object for this interrupt window handler
    ///
    external_interrupt_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~external_interrupt_handler() = default;

public:

    /// @cond

    bool handle(
        gsl::not_null<vcpu_t *> vcpu,
        ::eapis::intel_x64::external_interrupt_handler::info_t &info);

    /// @endcond

private:

    vcpu *m_vcpu;

public:

    /// @cond

    external_interrupt_handler(external_interrupt_handler &&) = default;
    external_interrupt_handler &operator=(external_interrupt_handler &&) = default;

    external_interrupt_handler(const external_interrupt_handler &) = delete;
    external_interrupt_handler &operator=(const external_interrupt_handler &) = delete;

    /// @endcond
};

}

#endif
