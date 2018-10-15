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
#include <hve/arch/intel_x64/vmcall/vcpu_op.h>

namespace hyperkernel::intel_x64
{

vmcall_vcpu_op_handler::vmcall_vcpu_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_vcpu_op_handler, dispatch)
    );
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__create_vcpu(
    gsl::not_null<vcpu_t *> vcpu)
{
    auto vcpuid = bfvmm::vcpu::generate_vcpuid();
    g_vcm->create(vcpuid, get_domain(vcpu->rcx()));

    return vcpuid;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__run_vcpu(
    gsl::not_null<vcpu_t *> vcpu)
{
    // Note:
    //
    // This code is executed on every interrupt, so keep this code as small
    // as possible. For this reason, we don't use an arg structure, preventing
    // the need to map in memory on every interrupt.
    //

    auto child_vcpu = get_hk_vcpu(vcpu->rcx());
    child_vcpu->set_parent_vcpu(m_vcpu);

    if (!child_vcpu->is_killed()) {
        child_vcpu->load();
        child_vcpu->run();
    }

    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__set_rip(
    gsl::not_null<vcpu_t *> vcpu)
{
    auto child_vcpu = get_hk_vcpu(vcpu->rcx());
    child_vcpu->set_rip(vcpu->rdx());

    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__set_rbx(
    gsl::not_null<vcpu_t *> vcpu)
{
    auto child_vcpu = get_hk_vcpu(vcpu->rcx());
    child_vcpu->set_rbx(vcpu->rdx());

    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__hlt_vcpu(
    gsl::not_null<vcpu_t *> vcpu)
{
    auto child_vcpu = get_hk_vcpu(vcpu->rcx());
    child_vcpu->kill();

    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__destroy_vcpu(
    gsl::not_null<vcpu_t *> vcpu)
{
    g_vcm->destroy(vcpu->rcx(), nullptr);
    return SUCCESS;
}

uint64_t
vmcall_vcpu_op_handler::vcpu_op__send_interrupt(
    gsl::not_null<vcpu_t *> vcpu)
{
    auto child_vcpu = get_hk_vcpu(vcpu->rcx());
    child_vcpu->send_interrupt(vcpu->rcx(), vcpu->rdx());
}

bool
vmcall_vcpu_op_handler::dispatch(
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __enum_vcpu_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_vcpu_op__create_vcpu:
        {
            auto vcpu_op__create_vcpu_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__create_vcpu);

            return guard_vmcall(vcpu, vcpu_op__create_vcpu_delegate);
        }

        case __enum_vcpu_op__run_vcpu:
        {
            auto vcpu_op__run_vcpu_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__run_vcpu);

            return guard_vmcall(vcpu, vcpu_op__run_vcpu_delegate);
        }

        case __enum_vcpu_op__set_rip:
        {
            auto vcpu_op__set_rip_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__set_rip);

            return guard_vmcall(vcpu, vcpu_op__set_rip_delegate);
        }

        case __enum_vcpu_op__set_rbx:
        {
            auto vcpu_op__set_rbx_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__set_rbx);

            return guard_vmcall(vcpu, vcpu_op__set_rbx_delegate);
        }

        case __enum_vcpu_op__hlt_vcpu:
        {
            auto vcpu_op__hlt_vcpu_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__hlt_vcpu);

            return guard_vmcall(vcpu, vcpu_op__hlt_vcpu_delegate);
        }

        case __enum_vcpu_op__destroy_vcpu:
        {
            auto vcpu_op__destroy_vcpu_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__destroy_vcpu);

            return guard_vmcall(vcpu, vcpu_op__destroy_vcpu_delegate);
        }

        case __enum_vcpu_op__send_interrupt:
        {
            auto vcpu_op__send_interrupt_delegate =
                guard_vmcall_delegate(vmcall_vcpu_op_handler, vcpu_op__send_interrupt);

            return guard_vmcall(vcpu, vcpu_op__send_interrupt_delegate);
        }

        default:
            break;
    };

    throw std::runtime_error("unknown vcpu opcode");
}

}
