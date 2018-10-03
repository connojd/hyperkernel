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
#include <hve/arch/intel_x64/vmexit/external_interrupt.h>

namespace hyperkernel::intel_x64
{

external_interrupt_handler::external_interrupt_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    // if (vcpuid::is_guest_vm_vcpu(m_apis->m_vmcs->vcpuid())) {
    //     m_vcpu->add_external_interrupt_handler(
    //         eapis::intel_x64::external_interrupt_handler::handler_delegate_t::create<
    //             external_interrupt_handler, &external_interrupt_handler::handle>(this)
    //     );
    // }
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
external_interrupt_handler::handle(
    gsl::not_null<vmcs_t *> vmcs,
    eapis::intel_x64::external_interrupt_handler::info_t &info)
{
    bfignored(vmcs);

bfline
    auto vcpu = get_hk_vcpu(m_vcpu->parent_vcpuid());


// AHAHAHAHAH
//
//
// Need to load the vCPU first, before making mods. We need to talk to Connor
// about this tomrrow.
//
//




    vcpu->queue_external_interrupt(info.vector);
    m_vcpu->resume_parent();

    return true;
}

}
