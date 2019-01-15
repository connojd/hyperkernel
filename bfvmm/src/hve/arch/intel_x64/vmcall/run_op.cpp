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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmcall/run_op.h>

namespace hyperkernel::intel_x64
{

vmcall_run_op_handler::vmcall_run_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_child_vcpu{nullptr}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_run_op_handler, dispatch)
    );
}

bool
vmcall_run_op_handler::dispatch(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __enum_run_op) {
        return false;
    }

    try {
        if (m_child_vcpu == nullptr ||
            m_child_vcpu->id() != vcpu->rbx()
        ) {
            m_child_vcpu = get_vcpu(vcpu->rbx());
        }

        m_child_vcpu->set_parent_vcpu(vcpu);

        if (m_child_vcpu->is_alive()) {
            m_child_vcpu->load();
            m_child_vcpu->run(&world_switch);
        }

        vcpu->set_rax(__enum_run_op__hlt);
    }
    catchall({
        vcpu->set_rax(__enum_run_op__fault);
    })

    return true;
}

}
