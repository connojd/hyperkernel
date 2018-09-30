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

#include <hve/arch/intel_x64/apis.h>
#include <hve/arch/intel_x64/vcpu_guest.h>

namespace hyperkernel::intel_x64
{

vmcall_vcpu_op_handler::vmcall_vcpu_op_handler(
    gsl::not_null<apis *> apis
) :
    m_apis{apis}
{
    using namespace vmcs_n;

    apis->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_vcpu_op_handler, dispatch)
    );
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__create_vcpu(
    gsl::not_null<vmcs_t *> vmcs)
{
    auto vcpu_op__create_vcpu_arg =
        get_hypercall_arg<__vcpu_op__create_vcpu_arg_t>(vmcs);

    vcpu_guest_state_t vcpu_guest_state {
        get_domain(vcpu_op__create_vcpu_arg->domainid)
    };

    auto vcpuid = bfvmm::vcpu::generate_vcpuid();
    g_vcm->create(vcpuid, &vcpu_guest_state);

    return vcpuid;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__run_vcpu(
    gsl::not_null<vmcs_t *> vmcs)
{
    auto vcpu_op__run_vcpu_arg =
        get_hypercall_arg<__vcpu_op__run_vcpu_arg_t>(vmcs);

    auto vcpu = get_guest_vcpu(vcpu_op__run_vcpu_arg->vcpuid);
    vcpu->hkapis()->set_parent_vmcs(vmcs);

    vcpu->launch();
    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__set_entry(
    gsl::not_null<vmcs_t *> vmcs)
{
    auto vcpu_op__set_entry_arg =
        get_hypercall_arg<__vcpu_op__set_entry_arg_t>(vmcs);

    auto vcpu = get_guest_vcpu(vcpu_op__set_entry_arg->vcpuid);
    vcpu->vmcs()->save_state()->rip = vcpu_op__set_entry_arg->entry;

    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__set_stack(
    gsl::not_null<vmcs_t *> vmcs)
{
    auto vcpu_op__set_stack_arg =
        get_hypercall_arg<__vcpu_op__set_stack_arg_t>(vmcs);

    auto vcpu = get_guest_vcpu(vcpu_op__set_stack_arg->vcpuid);
    vcpu->vmcs()->save_state()->rsp = vcpu_op__set_stack_arg->stack;

    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__hlt_vcpu(
    gsl::not_null<vmcs_t *> vmcs)
{
    bfignored(vmcs);
    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__destroy_vcpu(
    gsl::not_null<vmcs_t *> vmcs)
{
    auto vcpu_op__destroy_vcpu_arg =
        get_hypercall_arg<__vcpu_op__destroy_vcpu_arg_t>(vmcs);

    g_vcm->destroy(vcpu_op__destroy_vcpu_arg->vcpuid, nullptr);
    return SUCCESS;
}

bool
vmcall_vcpu_op_handler::dispatch(
    gsl::not_null<vmcs_t *> vmcs)
{
    if (vmcs->save_state()->rax != __enum_vcpu_op) {
        return false;
    }

    switch(vmcs->save_state()->rbx) {
        case __enum_vcpu_op__create_vcpu:
        {
            auto vcpu_op__create_vcpu_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__create_vcpu);

            return guard_vmcall(vmcs, vcpu_op__create_vcpu_delegate);
        }

        case __enum_vcpu_op__run_vcpu:
        {
            auto vcpu_op__run_vcpu_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__run_vcpu);

            return guard_vmcall(vmcs, vcpu_op__run_vcpu_delegate);
        }

        case __enum_vcpu_op__set_entry:
        {
            auto vcpu_op__set_entry_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__set_entry);

            return guard_vmcall(vmcs, vcpu_op__set_entry_delegate);
        }

        case __enum_vcpu_op__set_stack:
        {
            auto vcpu_op__set_stack_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__set_stack);

            return guard_vmcall(vmcs, vcpu_op__set_stack_delegate);
        }

        case __enum_vcpu_op__hlt_vcpu:
        {
            auto vcpu_op__hlt_vcpu_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__hlt_vcpu);

            return guard_vmcall(vmcs, vcpu_op__hlt_vcpu_delegate);
        }

        case __enum_vcpu_op__destroy_vcpu:
        {
            auto vcpu_op__destroy_vcpu_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__destroy_vcpu);

            return guard_vmcall(vmcs, vcpu_op__destroy_vcpu_delegate);
        }

        default:
            break;
    };

    throw std::runtime_error("unknown vcpu opcode");
}

}
