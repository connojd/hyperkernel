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

#ifndef VCPU_INTEL_X64_HYPERKERNEL_H
#define VCPU_INTEL_X64_HYPERKERNEL_H

#include <eapis/hve/arch/intel_x64/vcpu.h>

namespace hyperkernel
{
namespace intel_x64
{

/// vCPU
///
class vcpu : public eapis::intel_x64::vcpu
{

public:

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param id the id of this vcpu
    ///
    explicit vcpu(
        vcpuid::type id
    ) :
        eapis::intel_x64::vcpu(id)
    {
        exit_handler()->add_handler(
            vmcs_n::exit_reason::basic_exit_reason::vmcall,
            ::handler_delegate_t::create<vcpu, &vcpu::vmcall_handler>(this)
        );
    }

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vcpu() = default;

private:

    bool
    vmcall_handler(
        gsl::not_null<vmcs_t *> vmcs)
    {
        guard_exceptions([&] {
            vmcs->save_state()->rax = 0x1;
        });

        return advance(vmcs);
    }
};

}
}

#endif
