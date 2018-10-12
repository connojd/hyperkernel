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
#include <hve/arch/intel_x64/vmcall/domain_op.h>

namespace hyperkernel::intel_x64
{

vmcall_domain_op_handler::vmcall_domain_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_domain_op_handler, dispatch)
    );
}

uint64_t
vmcall_domain_op_handler::domain_op__create_domain(
    gsl::not_null<vcpu_t *> vcpu)
{
    bfignored(vcpu);

    auto domainid = domain::generate_domainid();
    g_dm->create(domainid, nullptr);

    return domainid;
}

uint64_t
vmcall_domain_op_handler::domain_op__map_md(
    gsl::not_null<vcpu_t *> vcpu)
{
    auto domain_op__map_md_arg =
        get_hypercall_arg<__domain_op__map_md_arg_t>(vcpu);

    auto phys_addr =
        bfvmm::x64::virt_to_phys_with_cr3(
            domain_op__map_md_arg->virt_addr,
            vmcs_n::guest_cr3::get()
        );

    get_domain(domain_op__map_md_arg->domainid)->map_4k(
        domain_op__map_md_arg->exec_addr, phys_addr
    );

    return SUCCESS;
}

uint64_t
vmcall_domain_op_handler::domain_op__map_commit(
    gsl::not_null<vcpu_t *> vcpu)
{
    get_domain(vcpu->rcx())->map_commit();
    return SUCCESS;
}

uint64_t
vmcall_domain_op_handler::domain_op__destroy_domain(
    gsl::not_null<vcpu_t *> vcpu)
{
    g_dm->destroy(vcpu->rcx(), nullptr);
    return SUCCESS;
}

bool
vmcall_domain_op_handler::dispatch(
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __enum_domain_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_domain_op__create_domain:
        {
            auto domain_op__create_domain_delegate =
                guard_vmcall_delegate(vmcall_domain_op_handler, domain_op__create_domain);

            return guard_vmcall(vcpu, domain_op__create_domain_delegate);
        }

        case __enum_domain_op__map_md:
        {
            auto domain_op__map_md_delegate =
                guard_vmcall_delegate(vmcall_domain_op_handler, domain_op__map_md);

            return guard_vmcall(vcpu, domain_op__map_md_delegate);
        }

        case __enum_domain_op__map_commit:
        {
            auto domain_op__map_commit_delegate =
                guard_vmcall_delegate(vmcall_domain_op_handler, domain_op__map_commit);

            return guard_vmcall(vcpu, domain_op__map_commit_delegate);
        }

        case __enum_domain_op__destroy_domain:
        {
            auto domain_op__destroy_domain_delegate =
                guard_vmcall_delegate(vmcall_domain_op_handler, domain_op__destroy_domain);

            return guard_vmcall(vcpu, domain_op__destroy_domain_delegate);
        }

        default:
            break;
    };

    throw std::runtime_error("unknown domain opcode");
}

}
