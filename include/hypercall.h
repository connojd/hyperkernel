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

void _pause(void) NOEXCEPT;
uint64_t _vmcall(uint64_t r1, uint64_t r2, uint64_t r3, uint64_t r4) NOEXCEPT;

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

#define __enum_domain_op 0xBF5C000000000100
#define __enum_vcpu_op 0xBF5C000000000200
#define __enum_bf86_op 0xBF86000000000100

// -----------------------------------------------------------------------------
// Domain Operations
// -----------------------------------------------------------------------------

#define __enum_domain_op__create_domain 0x100
#define __enum_domain_op__destroy_domain 0x101
#define __enum_domain_op__map_md 0x110
#define __enum_domain_op__map_commit 0x111

typedef struct {
    domainid_t domainid;
} __domain_op__destroy_domain_arg_t;

typedef struct {
    domainid_t domainid;
    uint64_t virt_addr;
    uint64_t exec_addr;
} __domain_op__map_md_arg_t;

typedef struct {
    domainid_t domainid;
} __domain_op__map_commit_arg_t;

static inline domainid_t
__domain_op__create_domain()
{
    return _vmcall(
        __enum_domain_op,
        __enum_domain_op__create_domain,
        0,
        0
    );
}

static inline status_t
__domain_op__destroy_domain(domainid_t domainid)
{
    __domain_op__destroy_domain_arg_t arg = {
        domainid
    };

    status_t ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__destroy_domain,
        bfrcast(uint64_t, &arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
__domain_op__map_md(
    domainid_t domainid, uint64_t virt_addr, uint64_t exec_addr)
{
    __domain_op__map_md_arg_t arg = {
        domainid, virt_addr, exec_addr
    };

    status_t ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__map_md,
        bfrcast(uint64_t, &arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
__domain_op__map_commit(domainid_t domainid)
{
    __domain_op__map_commit_arg_t arg = {
        domainid
    };

    status_t ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__map_commit,
        bfrcast(uint64_t, &arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

// -----------------------------------------------------------------------------
// vCPU Operations
// -----------------------------------------------------------------------------

#define __enum_vcpu_op__create_vcpu 0x100
#define __enum_vcpu_op__run_vcpu 0x101
#define __enum_vcpu_op__hlt_vcpu 0x102
#define __enum_vcpu_op__destroy_vcpu 0x103
#define __enum_vcpu_op__set_entry 0x110
#define __enum_vcpu_op__set_stack 0x111

typedef struct {
    domainid_t domainid;
} __vcpu_op__create_vcpu_arg_t;

typedef struct {
    vcpuid_t vcpuid;
} __vcpu_op__destroy_vcpu_arg_t;

typedef struct {
    vcpuid_t vcpuid;
    uint64_t entry;
} __vcpu_op__set_entry_arg_t;

typedef struct {
    vcpuid_t vcpuid;
    uint64_t stack;
} __vcpu_op__set_stack_arg_t;

static inline vcpuid_t
__vcpu_op__create_vcpu(domainid_t domainid)
{
    __vcpu_op__create_vcpu_arg_t arg = {
        domainid
    };

    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__create_vcpu,
        bfrcast(uint64_t, &arg),
        0
    );
}

static inline status_t
__vcpu_op__run_vcpu(vcpuid_t vcpuid)
{
    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__run_vcpu,
        vcpuid,
        0
    );
}

static inline status_t
__vcpu_op__hlt_vcpu(vcpuid_t vcpuid)
{
    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__hlt_vcpu,
        vcpuid,
        0
    );
}

static inline status_t
__vcpu_op__destroy_vcpu(vcpuid_t vcpuid)
{
    __vcpu_op__destroy_vcpu_arg_t arg = {
        vcpuid
    };

    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__destroy_vcpu,
        bfrcast(uint64_t, &arg),
        0
    );
}

static inline status_t
__vcpu_op__set_entry(vcpuid_t vcpuid, uint64_t entry)
{
    __vcpu_op__set_entry_arg_t arg = {
        vcpuid, entry
    };

    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__set_entry,
        bfrcast(uint64_t, &arg),
        0
    );
}

static inline status_t
__vcpu_op__set_stack(vcpuid_t vcpuid, uint64_t stack)
{
    __vcpu_op__set_stack_arg_t arg = {
        vcpuid, stack
    };

    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__set_stack,
        bfrcast(uint64_t, &arg),
        0
    );
}

// -----------------------------------------------------------------------------
// Bareflank x86 Instruction Emulation Operations
// -----------------------------------------------------------------------------

#define __enum_bf86_op__emulate_outb 0x6E
#define __enum_bf86_op__emulate_hlt 0xF4

static inline status_t
__bf86_op__emulate_outb(char byte)
{
    return _vmcall(
        __enum_bf86_op,
        __enum_bf86_op__emulate_outb,
        byte,
        0
    );
}

static inline status_t
__bf86_op__emulate_hlt()
{
    return _vmcall(
        __enum_bf86_op,
        __enum_bf86_op__emulate_hlt,
        0,
        0
    );
}

#pragma pack(pop)

#endif
