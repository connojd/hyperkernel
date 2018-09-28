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

#include <bfvmm/vcpu/vcpu_manager.h>
#include <bfvmm/memory_manager/arch/x64/unique_map.h>

#include <domain/domain_manager.h>

#include <hve/arch/intel_x64/apis.h>
#include <hve/arch/intel_x64/vcpu_guest.h>
#include <hve/arch/intel_x64/vmcall/vcpu.h>

namespace hyperkernel::intel_x64
{

static bool
create_vcpu(
    gsl::not_null<vmcs_t *> vmcs)
{
    guard_exceptions([&] {

        auto map =
            bfvmm::x64::make_unique_map<vcpu_op__create_vcpu_arg_t>(
                vmcs->save_state()->rcx,
                vmcs_n::guest_cr3::get(),
                sizeof(vcpu_op__create_vcpu_arg_t)
            );

        vcpu_guest_state_t vcpu_guest_state {
            get_domain(map->domainid)
        };

        vmcs->save_state()->rax = bfvmm::vcpu::generate_vcpuid();
        g_vcm->create(vmcs->save_state()->rax, &vcpu_guest_state);
    },
    [&] {
        vmcs->save_state()->rax = vcpuid::invalid;
    });

    vmcs->load();
    return true;
}

static bool
run_vcpu(
    gsl::not_null<vmcs_t *> vmcs)
{
    using namespace ::intel_x64::vmcs;

    guard_exceptions([&] {

        auto map =
            bfvmm::x64::make_unique_map<vcpu_op__run_vcpu_arg_t>(
                vmcs->save_state()->rcx,
                vmcs_n::guest_cr3::get(),
                sizeof(vcpu_op__run_vcpu_arg_t)
            );

        auto vcpu = get_guest_vcpu(map->vcpuid);
        vcpu->load();

        guest_rip::set(map->rip);
        guest_rsp::set(map->rsp);

        vcpu->launch();
        vmcs->save_state()->rax = SUCCESS;
    },
    [&] {
        vmcs->save_state()->rax = SUCCESS;
    });

    vmcs->load();
    return true;
}

static bool
dispatch(
    gsl::not_null<vmcs_t *> vmcs)
{
    if (vmcs->save_state()->rax != __vcpu_op) {
        return false;
    }

    switch(vmcs->save_state()->rbx) {
        case __vcpu_op__create_vcpu:
            return create_vcpu(vmcs);

        case __vcpu_op__run_vcpu:
            return run_vcpu(vmcs);

        default:
            break;
    };

    throw std::runtime_error("unknown vcpu opcode");
}

vmcall_vcpu_handler::vmcall_vcpu_handler(
    gsl::not_null<apis *> apis)
{
    using namespace vmcs_n;

    apis->add_vmcall_handler(
        vmcall_handler::handler_delegate_t::create<dispatch>()
    );
}

}
