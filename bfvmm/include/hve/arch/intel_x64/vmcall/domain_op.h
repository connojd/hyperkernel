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

#ifndef VMCALL_DOMAIN_INTEL_X64_HYPERKERNEL_H
#define VMCALL_DOMAIN_INTEL_X64_HYPERKERNEL_H

#include "base.h"

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class EXPORT_HYPERKERNEL_HVE vmcall_domain_op_handler
{
public:

    vmcall_domain_op_handler(
        gsl::not_null<apis *> apis);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_domain_op_handler() = default;

private:

    uint64_t domain_op__create_domain(gsl::not_null<vmcs_t *> vmcs);
    uint64_t domain_op__map_md(gsl::not_null<vmcs_t *> vmcs);
    uint64_t domain_op__map_commit(gsl::not_null<vmcs_t *> vmcs);
    uint64_t domain_op__destroy_domain(gsl::not_null<vmcs_t *> vmcs);

    bool dispatch(gsl::not_null<vmcs_t *> vmcs);

private:

    apis *m_apis;

public:

    /// @cond

    vmcall_domain_op_handler(vmcall_domain_op_handler &&) = default;
    vmcall_domain_op_handler &operator=(vmcall_domain_op_handler &&) = default;

    vmcall_domain_op_handler(const vmcall_domain_op_handler &) = delete;
    vmcall_domain_op_handler &operator=(const vmcall_domain_op_handler &) = delete;

    /// @endcond
};

}

#endif