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

#include <intrinsics.h>
#include <hve/arch/intel_x64/vcpu.h>

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

namespace hyperkernel
{
namespace intel_x64
{

vcpu::vcpu(
    vcpuid::type id,
    hyperkernel::intel_x64::domain *domain
) :
    eapis::intel_x64::vcpu{
        id,
        domain != nullptr ? domain->global_state() : nullptr
    },

    m_domain{domain},

    m_external_interrupt_handler{this},
    m_fault_handler{this},
    m_vmcall_handler{this},

    m_vmcall_domain_op_handler{this},
    m_vmcall_vcpu_op_handler{this},
    m_vmcall_bf86_op_handler{this}
{
    if (this->is_guest_vm_vcpu()) {
        this->write_guest_state(domain);
    }
}

//==========================================================================
// VMExit
//==========================================================================

//--------------------------------------------------------------------------
// VMCall
//--------------------------------------------------------------------------

gsl::not_null<vmcall_handler *>
vcpu::vmcall()
{ return &m_vmcall_handler; }

void
vcpu::add_vmcall_handler(
    const vmcall_handler::handler_delegate_t &d)
{ m_vmcall_handler.add_handler(std::move(d)); }

//--------------------------------------------------------------------------
// Parent vCPU
//--------------------------------------------------------------------------

void
vcpu::set_parent_vcpu(gsl::not_null<vcpu *> vcpu)
{ m_parent_vcpu = vcpu; }

vcpu *
vcpu::parent_vcpu() const
{ return m_parent_vcpu; }

void
vcpu::return_success()
{
    vmcs()->save_state()->rax = SUCCESS;

    this->advance();
    this->run();
}

void
vcpu::return_failure()
{
    vmcs()->save_state()->rax = FAILURE;

    this->advance();
    this->run();
}

void
vcpu::return_and_continue()
{
    vmcs_n::guest_rflags::carry_flag::enable();

    this->advance();
    this->run();
}

}
}
