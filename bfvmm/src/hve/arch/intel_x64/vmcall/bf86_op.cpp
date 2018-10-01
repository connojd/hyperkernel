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
#include <hve/arch/intel_x64/apis.h>

namespace hyperkernel::intel_x64
{

vmcall_bf86_op_handler::vmcall_bf86_op_handler(
    gsl::not_null<apis *> apis
) :
    m_apis{apis}
{
    using namespace vmcs_n;

    apis->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_bf86_op_handler, dispatch)
    );
}

uint64_t
vmcall_bf86_op_handler::bf86_op__emulate_outb(
    gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);

    std::cout << gsl::narrow_cast<char>(vmcs->save_state()->rcx);
    return SUCCESS;
}

uint64_t
vmcall_bf86_op_handler::bf86_op__emulate_hlt(
    gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);

    m_apis->resume();
    return SUCCESS;
}

bool
vmcall_bf86_op_handler::dispatch(
    gsl::not_null<vmcs_t *> vmcs)
{
    if (vmcs->save_state()->rax != __enum_bf86_op) {
        return false;
    }

    switch(vmcs->save_state()->rbx) {
        case __enum_bf86_op__emulate_outb:
        {
            auto bf86_op__emulate_outb_delegate =
                guard_vmcall_delegate(vmcall_bf86_op_handler, bf86_op__emulate_outb);

            return guard_vmcall(vmcs, bf86_op__emulate_outb_delegate);
        }

        case __enum_bf86_op__emulate_hlt:
        {
            auto bf86_op__emulate_hlt_delegate =
                guard_vmcall_delegate(vmcall_bf86_op_handler, bf86_op__emulate_hlt);

            return guard_vmcall(vmcs, bf86_op__emulate_hlt_delegate);
        }

        default:
            break;
    };

    throw std::runtime_error("unknown bf86 opcode");
}


}
