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
#include <hve/arch/intel_x64/vmexit/vmcall.h>

namespace hyperkernel::intel_x64
{

vmcall_handler::vmcall_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_handler(
        exit_reason::basic_exit_reason::vmcall,
        ::handler_delegate_t::create<vmcall_handler, &vmcall_handler::handle>(this)
    );
}

// -----------------------------------------------------------------------------
// Add Handler / Enablers
// -----------------------------------------------------------------------------

void
vmcall_handler::add_handler(
    const handler_delegate_t &d)
{ m_handlers.push_front(d); }

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

static bool
vmcall_error(gsl::not_null<vcpu *> vcpu, const std::string &str)
{
    bfdebug_transaction(0, [&](std::string * msg) {

        bferror_lnbr(0, msg);
        bferror_info(0, ("vmcall error: " + str).c_str(), msg);
        bferror_brk1(0, msg);

        if ((vcpu->rax() & 0xFFFF000000000000) == 0xBF5C000000000000) {
            bferror_subnhex(0, "rax", vcpu->rax(), msg);
            bferror_subnhex(0, "rbx", vcpu->rbx(), msg);
            bferror_subnhex(0, "rcx", vcpu->rcx(), msg);
            bferror_subnhex(0, "rdx", vcpu->rdx(), msg);
        }
        else {
            bferror_subnhex(0, "rax", vcpu->rax(), msg);
            bferror_subnhex(0, "rdi", vcpu->rdi(), msg);
        }
    });

    if (vcpu->is_domU()) {
        vcpu->halt(str);
    }

    vcpu->set_rax(FAILURE);
    return true;
}

bool
vmcall_handler::handle(gsl::not_null<vcpu_t *> vcpu)
{
    auto ___ = gsl::finally([&]{
        vcpu->load();
    });

    vcpu->advance();

    if ((vcpu->rax() & 0xBFFF) == 0xBFFF) {
        bfdebug_nhex(0, "ping id", vcpu->rcx());
        return true;
    }

    try {
        for (const auto &d : m_handlers) {
            if (d(m_vcpu)) {
                return true;
            }
        }
    }
    catchall({
        return vmcall_error(m_vcpu, "vmcall threw exception");
    })

    return vmcall_error(m_vcpu, "unknown vmcall");
}

}
