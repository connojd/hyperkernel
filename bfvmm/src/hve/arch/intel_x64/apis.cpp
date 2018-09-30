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

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

namespace hyperkernel
{
namespace intel_x64
{

apis::apis(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
    gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler,
    domain *domain
) :
    m_vmcs{vmcs},
    m_exit_handler{exit_handler},
    m_domain{domain},

    m_parent_vmcs{},

    m_fault_handler{this},
    m_vmcall_handler{this},

    m_vmcall_domain_op_handler{this},
    m_vmcall_vcpu_op_handler{this},
    m_vmcall_bf86_op_handler{this}
{ }

//==========================================================================
// VMExit
//==========================================================================

//--------------------------------------------------------------------------
// VMCall
//--------------------------------------------------------------------------

gsl::not_null<vmcall_handler *>
apis::vmcall()
{ return &m_vmcall_handler; }

void
apis::add_vmcall_handler(
    const vmcall_handler::handler_delegate_t &d)
{ m_vmcall_handler.add_handler(std::move(d)); }

//--------------------------------------------------------------------------
// Parent VMCS
//--------------------------------------------------------------------------

void
apis::set_parent_vmcs(gsl::not_null<vmcs_t *> vmcs)
{ m_parent_vmcs = vmcs; }

void
apis::resume_parent_vmcs(uint64_t status)
{
    if (m_parent_vmcs != nullptr) {
        m_parent_vmcs->load();
        advance(m_parent_vmcs);
        m_parent_vmcs->save_state()->rax = status;
        vmcs_resume(m_parent_vmcs->save_state());
    }

    throw std::runtime_error("parent vmcs never set");
}

//==========================================================================
// Resources
//==========================================================================

void
apis::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handler->add_handler(reason, d); }

}
}
