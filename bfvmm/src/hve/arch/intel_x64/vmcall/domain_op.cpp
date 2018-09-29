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

#include <hypercall.h>
#include <domain/domain_manager.h>
#include <hve/arch/intel_x64/apis.h>

#include <bfvmm/memory_manager/arch/x64/unique_map.h>

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
    });

    return true;
}

static bool
map_4k(
    gsl::not_null<vmcs_t *> vmcs)
{
    guard_exceptions([&] {

        auto map =
            bfvmm::x64::make_unique_map<domain_op__map_4k_arg_t>(
                vmcs->save_state()->rcx,
                vmcs_n::guest_cr3::get(),
                sizeof(domain_op__map_4k_arg_t)
            );

        auto phys_addr =
            bfvmm::x64::virt_to_phys_with_cr3(
                map->virt_addr,
                vmcs_n::guest_cr3::get()
            );

        if (map->exec_addr == 0x0000000000301000) {
            get_domain(map->domainid)->map_4k(map->exec_addr, phys_addr);
        }

        get_domain(map->domainid)->map_4k(map->exec_addr, phys_addr);
        vmcs->save_state()->rax = SUCCESS;
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
    if (vmcs->save_state()->rax != __domain_op) {
        return false;
    }

    switch(vmcs->save_state()->rbx) {
        case __domain_op__create_domain:
            return create_domain(vmcs);

        case __domain_op__map_4k:
            return map_4k(vmcs);

        default:
            break;
    };

    throw std::runtime_error("unknown domain opcode");
}

vmcall_domain_op_handler::vmcall_domain_op_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_vmcall_handler(
        vmcall_handler::handler_delegate_t::create<dispatch>()
    );
}

}
