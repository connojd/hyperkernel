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
#include <hve/arch/intel_x64/vmcall/event_op.h>

template<typename T>
auto get_hypercall_arg(gsl::not_null<vcpu_t *> vcpu)
{ return vcpu_cast(vcpu)->map_gva_4k<T>(vcpu->rcx(), sizeof(T)); }

namespace hyperkernel::intel_x64
{

vmcall_event_op_handler::vmcall_event_op_handler(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_event_op_handler, dispatch)
    );
}

uint64_t
vmcall_event_op_handler::event_op__send(gsl::not_null<vcpu_t *> vcpu)
{
    auto event = get_hypercall_arg<__event_op__event_arg_t>(vcpu);

    bfdebug_info(0, "Event op: send");
    bfdebug_subnhex(0, "destination", event->dest);
    bfdebug_subnhex(0, "vector", event->vector);

    return SUCCESS;
}

bool
vmcall_event_op_handler::dispatch(gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __enum_event_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_event_op__send: {
            auto event_op__send_delegate =
                guard_vmcall_delegate(vmcall_event_op_handler,
                                      event_op__send);

            return guard_vmcall(vcpu, event_op__send_delegate);
        }

        default:
            break;
    };

    throw std::runtime_error("unknown event opcode");
}


}
