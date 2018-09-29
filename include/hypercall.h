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
#include <bfmemory.h>
#include <bferrorcodes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#ifdef __cplusplus
extern "C" {
#endif

uint32_t _cpuid_eax(uint32_t val) NOEXCEPT;
uintptr_t _vmcall(uintptr_t r1, uintptr_t r2, uintptr_t r3, uintptr_t r4) NOEXCEPT;

#ifdef __cplusplus
}
#endif

// -----------------------------------------------------------------------------
// Types
// -----------------------------------------------------------------------------

#define domainid_t uint64_t
#define vcpuid_t uint64_t

#define INVALID_DOMAINID 0xFFFFFFFFFFFFFFFF
#define INVALID_VCPUID 0xFFFFFFFFFFFFFFFF

// -----------------------------------------------------------------------------
// Opcodes
// -----------------------------------------------------------------------------

#define __domain_op 0xBF5C000000000100
#define __vcpu_op 0xBF5C000000000200
#define __bf86_op 0xBF86000000000100

// -----------------------------------------------------------------------------
// Ack
// -----------------------------------------------------------------------------

inline uintptr_t
ack()
{ return _cpuid_eax(0xBF00); }

// -----------------------------------------------------------------------------
// Domain Operations
// -----------------------------------------------------------------------------

#define __domain_op__create_domain 0x100
#define __domain_op__run_domain 0x101
#define __domain_op__hlt_domain 0x102
#define __domain_op__destroy_domain 0x103
#define __domain_op__map_4k 0x110

struct domain_op__create_domain_arg_t {
};

struct domain_op__run_domain_arg_t {
    domainid_t domainid;
};

struct domain_op__hlt_domain_arg_t {
    domainid_t domainid;
};

struct domain_op__destroy_domain_arg_t {
    domainid_t domainid;
};

struct domain_op__map_4k_arg_t {
    domainid_t domainid;
    uintptr_t virt_addr;
    uintptr_t exec_addr;
};

inline domainid_t
domain_op__create_domain(struct domain_op__create_domain_arg_t *arg)
{
    return _vmcall(
        __domain_op,
        __domain_op__create_domain,
        bfrcast(uintptr_t, arg),
        0
    );
}

inline status_t
domain_op__run_domain(struct domain_op__run_domain_arg_t *arg)
{
    auto ret = _vmcall(
        __domain_op,
        __domain_op__run_domain,
        bfrcast(uintptr_t, arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

inline status_t
domain_op__hlt_domain(struct domain_op__hlt_domain_arg_t *arg)
{
    auto ret = _vmcall(
        __domain_op,
        __domain_op__hlt_domain,
        bfrcast(uintptr_t, arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

inline status_t
domain_op__destroy_domain(struct domain_op__destroy_domain_arg_t *arg)
{
    auto ret = _vmcall(
        __domain_op,
        __domain_op__destroy_domain,
        bfrcast(uintptr_t, arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

inline status_t
domain_op__map_4k(struct domain_op__map_4k_arg_t *arg)
{
    auto ret = _vmcall(
        __domain_op,
        __domain_op__map_4k,
        bfrcast(uintptr_t, arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

// -----------------------------------------------------------------------------
// vCPU Operations
// -----------------------------------------------------------------------------

#define __vcpu_op__create_vcpu 0x100
#define __vcpu_op__run_vcpu 0x101

struct vcpu_op__create_vcpu_arg_t {
    domainid_t domainid;
};

struct vcpu_op__run_vcpu_arg_t {
    vcpuid_t vcpuid;
    uintptr_t rip;
    uintptr_t rsp;
};

inline vcpuid_t
vcpu_op__create_vcpu(struct vcpu_op__create_vcpu_arg_t *arg)
{
    return _vmcall(
        __vcpu_op,
        __vcpu_op__create_vcpu,
        bfrcast(uintptr_t, arg),
        0
    );
}

inline status_t
vcpu_op__run_vcpu(struct vcpu_op__run_vcpu_arg_t *arg)
{
    return _vmcall(
        __vcpu_op,
        __vcpu_op__run_vcpu,
        bfrcast(uintptr_t, arg),
        0
    );
}

// -----------------------------------------------------------------------------
// Bareflank x86 Instruction Emulation Operations
// -----------------------------------------------------------------------------

#define __bf86_op__emulate_outb 0x6E
#define __bf86_op__emulate_hlt 0xF4

#pragma pack(pop)

#endif
