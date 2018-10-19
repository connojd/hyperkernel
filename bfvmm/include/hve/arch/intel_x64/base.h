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

#ifndef BASE_INTEL_X64_HYPERKERNEL_H
#define BASE_INTEL_X64_HYPERKERNEL_H

#include <bfdebug.h>

#include <bfvmm/vcpu/vcpu_manager.h>
#include <bfvmm/hve/arch/intel_x64/vcpu.h>

#include "../../../domain/domain_manager.h"
#include "../../../../../include/hypercall.h"


// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

using guard_vmcall_delegate_t =
    delegate<uint64_t(gsl::not_null<vcpu_t *>)>;

#define guard_vmcall_delegate(a,b) \
    guard_vmcall_delegate_t::create<a, &a::b>(this)

/// Guard VMCall
///
/// Catches all exceptions and prints the exception that occurred. The point of
/// this function is to prevent any exception from bubbling beyond this point.
/// Also note that this function will set RAX on success or failure.
///
/// @expects
/// @ensures
///
/// @param func the function to run that is guarded
/// @param error_func the function to run when an exception occurs
///
inline bool
guard_vmcall(
    gsl::not_null<vcpu_t *> vcpu, guard_vmcall_delegate_t &d)
{
    try {
        vcpu->set_rax(d(vcpu));
        return true;
    }
    catchall({
        vcpu->set_rax(0xFFFFFFFFFFFFFFFF);
        return true;
    });
}


#endif
