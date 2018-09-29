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

#include <bfdebug.h>
#include <iostream>

#include <hypercall.h>
#include <hve/arch/intel_x64/apis.h>

#include <bfvmm/memory_manager/arch/x64/unique_map.h>





extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;




namespace hyperkernel::intel_x64
{

static bool
emulate_outb(
    gsl::not_null<vmcs_t *> vmcs)
{
    guard_exceptions([&] {

        auto phys_addr =
            g_domain->ept().virt_to_phys(vmcs->save_state()->rcx);

bffield_hex(phys_addr);

        auto map =
            bfvmm::x64::make_unique_map<char>(
                phys_addr
            );

        char *msg = map.get() + bfn::lower(vmcs->save_state()->rcx);

        std::cout << "msg: " << msg << '\n';

        g_vmcs->save_state()->rax = SUCCESS;

    },
    [&] {
        vmcs->save_state()->rax = FAILURE;
    });

    return true;
}

static bool
emulate_hlt(
    gsl::not_null<vmcs_t *> vmcs)
{
    guard_exceptions([&] {

        g_vmcs->load();
        advance(g_vmcs);
        g_vmcs->save_state()->rax = SUCCESS;
        vmcs_resume(g_vmcs->save_state());

    },
    [&] {
        vmcs->save_state()->rax = FAILURE;
    });

    return true;
}

static bool
dispatch(
    gsl::not_null<vmcs_t *> vmcs)
{
    if (vmcs->save_state()->rax != __bf86_op) {
        return false;
    }

    switch(vmcs->save_state()->rbx) {
        case __bf86_op__emulate_outb:
            return emulate_outb(vmcs);

        case __bf86_op__emulate_hlt:
            return emulate_hlt(vmcs);

        default:
            break;
    };

    throw std::runtime_error("unknown bf86 opcode");
}

vmcall_bf86_op_handler::vmcall_bf86_op_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_vmcall_handler(
        vmcall_handler::handler_delegate_t::create<dispatch>()
    );
}

}
