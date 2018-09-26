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

#include <bfdebug.h>
#include <hve/arch/intel_x64/apis.h>

namespace hyperkernel
{
namespace intel_x64
{

vmcall_handler::vmcall_handler(
    gsl::not_null<apis *> apis,
    gsl::not_null<hyperkernel_vcpu_state_t *> hyperkernel_vcpu_state)
{
    using namespace vmcs_n;
    bfignored(hyperkernel_vcpu_state);

    apis->add_handler(
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

bool
vmcall_handler::handle(gsl::not_null<vmcs_t *> vmcs)
{
    try {
        struct info_t info {};

        for (const auto &d : m_handlers) {
            if (d(vmcs, info)) {

                if (!info.ignore_advance) {
                    return advance(vmcs);
                }

                return true;
            }
        }
    }
    catch(...)
    { }

    return advance(vmcs);
}

}
}
