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
#include <bfvmm/vcpu/vcpu_manager.h>

extern "C" void vmcs_resume(
    bfvmm::intel_x64::save_state_t *save_state) noexcept;

namespace hyperkernel
{
namespace intel_x64
{

std::mutex s_mutex;
std::unordered_map<vcpuid::type, apis*> apis::s_apis;

apis::apis(
    gsl::not_null<bfvmm::intel_x64::vmcs *> vmcs,
    gsl::not_null<bfvmm::intel_x64::exit_handler *> exit_handler,
    domain *domain
) :
    m_vmcs{vmcs},
    m_exit_handler{exit_handler},
    m_domain{domain},

    m_parent_vcpuid{},

    m_fault_handler{this},
    m_vmcall_handler{this},

    m_vmcall_domain_op_handler{this},
    m_vmcall_vcpu_op_handler{this},
    m_vmcall_bf86_op_handler{this}
{
    std::lock_guard lock(s_mutex);
    s_apis[m_vmcs->save_state()->vcpuid] = this;
}

 ~apis()
 {
    std::lock_guard lock(s_mutex);
    s_apis.erase(m_vmcs->save_state()->vcpuid);
 }

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

void set_parent_vcpuid(vcpuid::type id)
{ m_parent_vcpuid = id; }

void resume()
{
    auto vcpu = get_vcpu(m_parent_vcpuid);

    vcpu->load();
    vcpu->advance_and_resume();
}

//==========================================================================
// Resources
//==========================================================================

void
apis::add_handler(
    ::intel_x64::vmcs::value_type reason,
    const handler_delegate_t &d)
{ m_exit_handler->add_handler(reason, d); }

gsl::not_null<apis *>
apis::find(vcpuid::type id)
{
    std::lock_guard lock(s_mutex);

    if (auto iter = s_apis.find(id); iter != s_apis.end()) {
        return s_apis->second;
    }

    throw std::runtime_error("unknown apis");
}


}
}
