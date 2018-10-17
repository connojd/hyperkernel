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

#ifndef FAULT_INTEL_X64_HYPERKERNEL_H
#define FAULT_INTEL_X64_HYPERKERNEL_H

#include "vcpu.h"

inline void
fault(gsl::not_null<vcpu_t *> vcpu)
{
    using namespace ::intel_x64::vmcs;

    bferror_lnbr(0);
    bferror_info(0, "killing guest");
    bferror_brk1(0);

    bferror_subnhex(0, "rax", vcpu->rax());
    bferror_subnhex(0, "rbx", vcpu->rbx());
    bferror_subnhex(0, "rcx", vcpu->rcx());
    bferror_subnhex(0, "rdx", vcpu->rdx());
    bferror_subnhex(0, "rbp", vcpu->rbp());
    bferror_subnhex(0, "rsi", vcpu->rsi());
    bferror_subnhex(0, "rdi", vcpu->rdi());
    bferror_subnhex(0, "r08", vcpu->r08());
    bferror_subnhex(0, "r09", vcpu->r09());
    bferror_subnhex(0, "r10", vcpu->r10());
    bferror_subnhex(0, "r11", vcpu->r11());
    bferror_subnhex(0, "r12", vcpu->r12());
    bferror_subnhex(0, "r13", vcpu->r13());
    bferror_subnhex(0, "r14", vcpu->r14());
    bferror_subnhex(0, "r15", vcpu->r15());
    bferror_subnhex(0, "rip", vcpu->rip());
    bferror_subnhex(0, "rsp", vcpu->rsp());

    bferror_subnhex(0, "cr0", guest_cr0::get());
    bferror_subnhex(0, "cr2", ::intel_x64::cr2::get());
    bferror_subnhex(0, "cr3", guest_cr3::get());
    bferror_subnhex(0, "cr4", guest_cr4::get());

    bferror_subnhex(0, "linear address", guest_linear_address::get());
    bferror_subnhex(0, "physical address", guest_physical_address::get());

    bferror_subtext(0, "exit reason", exit_reason::basic_exit_reason::description());
    bferror_subnhex(0, "exit qualification", exit_qualification::get());

    bfvmm::intel_x64::check::all();

    auto parent_vcpu =
        static_cast<hyperkernel::intel_x64::vcpu *>(vcpu.get())->parent_vcpu();

    parent_vcpu->load();
    parent_vcpu->return_failure();
}

#endif
