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

void
vmcall_vcpu_op_handler::vcpu_op__create_vcpu(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        vcpu->set_rax(bfvmm::vcpu::generate_vcpuid());
        g_vcm->create(vcpu->rax(), get_domain(vcpu->rcx()));
    }
    catchall({
        vcpu->set_rax(INVALID_VCPUID);
    })
}

void
vmcall_vcpu_op_handler::vcpu_op__run_vcpu(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (m_child_vcpu == nullptr || m_child_vcpu->id() != vcpu->rcx()) {
            m_child_vcpu = get_vcpu(vcpu->rcx());
        }

        m_child_vcpu->set_parent_vcpu(vcpu);

        if (m_child_vcpu->is_alive()) {
            m_child_vcpu->load();
            m_child_vcpu->run(&world_switch);
        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_vcpu_op_handler::vcpu_op__set_rip(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto child_vcpu = get_vcpu(vcpu->rcx());
        child_vcpu->set_rip(vcpu->rdx());

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_vcpu_op_handler::vcpu_op__set_rbx(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto child_vcpu = get_vcpu(vcpu->rcx());
        child_vcpu->set_rbx(vcpu->rdx());

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_vcpu_op_handler::vcpu_op__hlt_vcpu(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto child_vcpu = get_vcpu(vcpu->rcx());
        child_vcpu->kill();

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_vcpu_op_handler::vcpu_op__destroy_vcpu(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        g_vcm->destroy(vcpu->rcx(), nullptr);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_vcpu_op_handler::vcpu_op__wake_vcpu(gsl::not_null<vcpu *> vcpu)
{
    try {
        if (m_child_vcpu == nullptr || m_child_vcpu->id() != vcpu->rcx()) {
            m_child_vcpu = get_vcpu(vcpu->rcx());
        }

        expects(m_child_vcpu->is_asleep());

        m_child_vcpu->load();
        m_child_vcpu->wake(&world_switch);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

bool
vmcall_vcpu_op_handler::dispatch(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __enum_vcpu_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_vcpu_op__create_vcpu:
            this->vcpu_op__create_vcpu(vcpu);
            return true;

        case __enum_vcpu_op__run_vcpu:
            this->vcpu_op__run_vcpu(vcpu);
            return true;

        case __enum_vcpu_op__set_rip:
            this->vcpu_op__set_rip(vcpu);
            return true;

        case __enum_vcpu_op__set_rbx:
            this->vcpu_op__set_rbx(vcpu);
            return true;

        case __enum_vcpu_op__hlt_vcpu:
            this->vcpu_op__hlt_vcpu(vcpu);
            return true;

        case __enum_vcpu_op__destroy_vcpu:
            this->vcpu_op__destroy_vcpu(vcpu);
            return true;

        case __enum_vcpu_op__wake_vcpu:
            this->vcpu_op__wake_vcpu(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown vcpu opcode");
}

}
