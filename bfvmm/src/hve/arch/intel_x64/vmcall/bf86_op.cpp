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

#include <iostream>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmcall/bf86_op.h>

template<typename T>
auto get_hypercall_arg(gsl::not_null<vcpu_t *> vcpu)
{ return vcpu_cast(vcpu)->map_gva_4k<T>(vcpu->rcx(), sizeof(T)); }

namespace hyperkernel::intel_x64
{

vmcall_bf86_op_handler::vmcall_bf86_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_bf86_op_handler, dispatch)
    );
}

uint64_t
vmcall_bf86_op_handler::bf86_op__emulate_outb(
    gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);

    std::cout << gsl::narrow_cast<char>(vcpu->rcx());
    return SUCCESS;
}

uint64_t
vmcall_bf86_op_handler::bf86_op__emulate_hlt(
    gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);
    auto parent_vcpu = m_vcpu->parent_vcpu();

    parent_vcpu->load();
    parent_vcpu->return_success();

    // Unreachable
    return SUCCESS;
}

bool
vmcall_bf86_op_handler::dispatch(
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __enum_bf86_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_bf86_op__emulate_outb:
        {
            auto bf86_op__emulate_outb_delegate =
                guard_vmcall_delegate(vmcall_bf86_op_handler, bf86_op__emulate_outb);

            return guard_vmcall(vcpu, bf86_op__emulate_outb_delegate);
        }

        case __enum_bf86_op__emulate_hlt:
        {
            auto bf86_op__emulate_hlt_delegate =
                guard_vmcall_delegate(vmcall_bf86_op_handler, bf86_op__emulate_hlt);

            return guard_vmcall(vcpu, bf86_op__emulate_hlt_delegate);
        }

        default:
            break;
    };

    throw std::runtime_error("unknown bf86 opcode");
}


}
