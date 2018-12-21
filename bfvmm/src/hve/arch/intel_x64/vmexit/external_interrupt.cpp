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
#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/vmexit/external_interrupt.h>
#include "../../../../../include/hve/arch/intel_x64/vtd/vtd_sandbox.h"

namespace hyperkernel::intel_x64
{

external_interrupt_handler::external_interrupt_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu},
    m_xapic_map{nullptr}
{
    using namespace vmcs_n;

    if (vcpuid::is_guest_vm_vcpu(vcpu->id())) {
        m_vcpu->add_external_interrupt_handler(
            eapis::intel_x64::external_interrupt_handler::handler_delegate_t::create<
                external_interrupt_handler, &external_interrupt_handler::handle>(this)
        );
    }

    auto apic_base = ::intel_x64::msrs::ia32_apic_base::apic_base::get();
    m_xapic_map = m_vcpu->map_hpa_4k<uint8_t>(apic_base);
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

bool
external_interrupt_handler::handle(
    gsl::not_null<vcpu_t *> vcpu,
    eapis::intel_x64::external_interrupt_handler::info_t &info)
{
    bfignored(vcpu);

    if(info.vector == vtd_sandbox::g_visr_vector) {
        bfdebug_info(0, "Passing-through NIC interrupt -> NDVM");
        auto my_vcpu = vcpu_cast(vcpu);
        my_vcpu->queue_external_interrupt(vtd_sandbox::g_ndvm_vector);
        this->send_eoi();
        return true;
    }

    auto parent_vcpu = m_vcpu->parent_vcpu();

    parent_vcpu->load();
    if(info.vector != vtd_sandbox::g_visr_vector) {
        parent_vcpu->queue_external_interrupt(info.vector);
    }
    parent_vcpu->return_resume_after_interrupt();

    // Unreachable
    return true;
}

void
external_interrupt_handler::send_eoi()
{
    auto reg = reinterpret_cast<uint32_t *>(m_xapic_map.get() + 0xB0);
    *reg = 0;

    // TODO deal with compiler reordering
    ::intel_x64::barrier::wmb();
}

}
