//
// Bareflank Hyperkernel
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
#include <hve/arch/intel_x64/fault.h>
#include <hve/arch/intel_x64/vmexit/fault.h>

namespace hyperkernel::intel_x64
{

fault_handler::fault_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::triple_fault,
        ::handler_delegate_t::create<fault_handler, &fault_handler::handle>(this)
    );

    vcpu->add_handler(
        exit_reason::basic_exit_reason::ept_violation,
        ::handler_delegate_t::create<fault_handler, &fault_handler::handle>(this)
    );

    vcpu->add_handler(
        exit_reason::basic_exit_reason::ept_misconfiguration,
        ::handler_delegate_t::create<fault_handler, &fault_handler::handle>(this)
    );

    vcpu->add_handler(
        exit_reason::basic_exit_reason::vm_entry_failure_invalid_guest_state,
        ::handler_delegate_t::create<fault_handler, &fault_handler::handle>(this)
    );

    vcpu->add_handler(
        exit_reason::basic_exit_reason::vm_entry_failure_msr_loading,
        ::handler_delegate_t::create<fault_handler, &fault_handler::handle>(this)
    );

    vcpu->add_handler(
        exit_reason::basic_exit_reason::vm_entry_failure_machine_check_event,
        ::handler_delegate_t::create<fault_handler, &fault_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
fault_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    fault(vcpu);

    // Unreachable
    return true;
}

}
