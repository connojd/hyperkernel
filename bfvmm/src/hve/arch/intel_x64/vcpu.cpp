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
    m_parent_vcpuid{},

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
// Parent VMCS
//--------------------------------------------------------------------------

void
vcpu::set_parent_vcpuid(vcpuid::type id)
{ m_parent_vcpuid = id; }

vcpuid::type
vcpu::parent_vcpuid() const
{ return m_parent_vcpuid; }

void
vcpu::resume_parent()
{
    auto vcpu = get_vcpu(m_parent_vcpuid);

    vcpu->load();
    vcpu->advance_and_resume();
}

}
}
