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

#ifndef VCPU_HOST_INTEL_X64_HYPERKERNEL_H
#define VCPU_HOST_INTEL_X64_HYPERKERNEL_H

#include "apis.h"
#include <eapis/hve/arch/intel_x64/vcpu.h>

namespace hyperkernel::intel_x64
{

/// vCPU
///
class vcpu_host : public eapis::intel_x64::vcpu
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    ///
    /// @cond
    ///
    explicit vcpu_host(
        vcpuid::type id
    ) :
        eapis::intel_x64::vcpu(id),
        m_apis{
            vmcs(),
            exit_handler()
        }
    { }

    /// @endcond

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu_host() = default;

    /// APIs
    ///
    /// @expects
    /// @ensures
    ///
    /// @return a pointer to the hkapis
    ///
    gsl::not_null<apis *> hkapis()
    { return &m_apis; }

private:

    apis m_apis;
};

}

#endif
