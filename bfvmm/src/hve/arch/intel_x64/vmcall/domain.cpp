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

#include <hve/arch/intel_x64/apis.h>
#include <hve/arch/intel_x64/vmcall/domain.h>

#include <hypercall.h>
#include <domain/domain_manager.h>

namespace hyperkernel::intel_x64
{

static bool
create_domain(
    gsl::not_null<vmcs_t *> vmcs)
{
    guard_exceptions([&] {
        vmcs->save_state()->rax = domain::generate_domainid();
        g_dm->create(vmcs->save_state()->rax, nullptr);
    },
    [&] {
        vmcs->save_state()->rax = invalid_domainid;
        return false;
    });

    return true;
}

static bool
dispatch(
    gsl::not_null<vmcs_t *> vmcs, vmcall_handler::info_t &info)
{
    bfignored(info);

    if (vmcs->save_state()->rax != domain_op) {
        return false;
    }

    switch(vmcs->save_state()->rbx) {
        case domain_op__create_domain:
            return create_domain(vmcs);

        default:
            break;
    };

    throw std::runtime_error("unknown domain opcode");
}

vmcall_domain_handler::vmcall_domain_handler(
    gsl::not_null<apis *> apis,
    gsl::not_null<hyperkernel_vcpu_state_t *> hyperkernel_vcpu_state)
{
    using namespace vmcs_n;
    bfignored(hyperkernel_vcpu_state);

    apis->add_vmcall_handler(
        vmcall_handler::handler_delegate_t::create<dispatch>()
    );
}

}
