//
// Bareflank Extended APIs
//
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

#include <bfvmm/vcpu/vcpu_factory.h>

#include <hve/arch/intel_x64/vcpu_host.h>
#include <hve/arch/intel_x64/vcpu_guest.h>

namespace bfvmm
{

std::unique_ptr<vcpu>
vcpu_factory::make(vcpuid::type vcpuid, bfobject *obj)
{
    if (obj == nullptr) {
        return
            std::make_unique<hyperkernel::intel_x64::vcpu_host>(
                vcpuid
            );
    }
    else {
        return
            std::make_unique<hyperkernel::intel_x64::vcpu_guest>(
                vcpuid,
                dynamic_cast<hyperkernel::intel_x64::vcpu_guest_state_t *>(obj)
            );
    }
}

}
