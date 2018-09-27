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

#ifndef HYPERCALL_H
#define HYPERCALL_H

#include <bftypes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

uint32_t _cpuid_eax(uint32_t val);
uintptr_t _vmcall(uintptr_t r1, uintptr_t r2, uintptr_t r3, uintptr_t r4);

#ifdef __cplusplus
}
#endif

// -----------------------------------------------------------------------------
// Opcodes
// -----------------------------------------------------------------------------

#define domain_op 0xBF0C000000000100
#define vcpu_op 0xBF0C000000000200

// -----------------------------------------------------------------------------
// Ack
// -----------------------------------------------------------------------------

inline uintptr_t
ack()
{ return _cpuid_eax(0xBF00); }

// -----------------------------------------------------------------------------
// Domain Operations
// -----------------------------------------------------------------------------

#define domain_op__create_domain 0x100

struct create_domain_arg_t {
};

inline uint64_t
create_domain(struct create_domain_arg_t *arg)
{
    return _vmcall(
        domain_op,
        domain_op__create_domain,
        bfrcast(uintptr_t, arg),
        0
    );
}

// -----------------------------------------------------------------------------
// vCPU Operations
// -----------------------------------------------------------------------------

#define vcpu_op__create_vcpu 0x100

struct create_vcpu_arg_t {
    uint64_t domainid;
};

inline uintptr_t
create_vcpu(struct create_vcpu_arg_t *arg)
{
    return _vmcall(
        vcpu_op,
        vcpu_op__create_vcpu,
        bfrcast(uintptr_t, arg),
        0
    );
}

#pragma pack(pop)

#endif
