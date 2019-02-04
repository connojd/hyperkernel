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
#include <bfconstants.h>
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

#define SELF 0x7FF0

// -----------------------------------------------------------------------------
// Opcodes
// -----------------------------------------------------------------------------

#define __enum_domain_op 0xBF5C000000000100
#define __enum_run_op 0xBF5C000000000200
#define __enum_vcpu_op 0xBF5C000000000300
#define __enum_uart_op 0xBF5C000000000400

// -----------------------------------------------------------------------------
// Domain Operations
// -----------------------------------------------------------------------------

#define __enum_domain_op__create_domain 0x100
#define __enum_domain_op__destroy_domain 0x101
#define __enum_domain_op__share_page 0x110
#define __enum_domain_op__add_e820_entry 0x120
#define __enum_domain_op__set_entry 0x130
#define __enum_domain_op__set_uart 0x140
#define __enum_domain_op__set_pt_uart 0x141
#define __enum_domain_op__dump_uart 0x142

#define MAP_RO 1
#define MAP_RW 4
#define MAP_RWE 6

#define UART_MAX_BUFFER 0x4000

struct __domain_op__share_page_arg_t {
    domainid_t foreign_domainid;
    uint64_t self_gpa;
    uint64_t foreign_gpa;
    uint64_t type;
};

struct __domain_op__add_e820_entry_arg_t {
    domainid_t domainid;
    uint64_t addr;
    uint64_t size;
    uint32_t type;
};

static inline domainid_t
__domain_op__create_domain(void)
{
    return _vmcall(
        __enum_domain_op,
        __enum_domain_op__create_domain,
        0,
        0
    );
}

static inline status_t
__domain_op__destroy_domain(domainid_t foreign_domainid)
{
    status_t ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__destroy_domain,
        foreign_domainid,
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
__domain_op__share_page(
    domainid_t foreign_domainid, uint64_t self_gpa, uint64_t foreign_gpa, uint64_t type)
{
    status_t ret;

    struct __domain_op__share_page_arg_t arg;
    arg.foreign_domainid = foreign_domainid;
    arg.self_gpa = self_gpa;
    arg.foreign_gpa = foreign_gpa;
    arg.type = type;

    ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__share_page,
        bfrcast(uint64_t, &arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
__domain_op__add_e820_entry(
    domainid_t domainid, uint64_t addr, uint64_t size, uint32_t type)
{
    status_t ret;

    struct __domain_op__add_e820_entry_arg_t arg;
    arg.domainid = domainid;
    arg.addr = addr;
    arg.size = size;
    arg.type = type;

    ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__add_e820_entry,
        bfrcast(uint64_t, &arg),
        0
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
__domain_op__set_entry(domainid_t foreign_domainid, uint64_t gpa)
{
    status_t ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__set_entry,
        foreign_domainid,
        gpa
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
__domain_op__set_uart(domainid_t foreign_domainid, uint64_t uart)
{
    status_t ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__set_uart,
        foreign_domainid,
        uart
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline status_t
__domain_op__set_pt_uart(domainid_t foreign_domainid, uint64_t uart)
{
    status_t ret = _vmcall(
        __enum_domain_op,
        __enum_domain_op__set_pt_uart,
        foreign_domainid,
        uart
    );

    return ret == 0 ? SUCCESS : FAILURE;
}

static inline uint64_t
__domain_op__dump_uart(domainid_t domainid, char *buffer)
{
    return _vmcall(
        __enum_domain_op,
        __enum_domain_op__dump_uart,
        domainid,
        bfrcast(uint64_t, buffer)
    );
}

// -----------------------------------------------------------------------------
// Run Operations
// -----------------------------------------------------------------------------

#define __enum_run_op__hlt 0x0
#define __enum_run_op__fault 0x1
#define __enum_run_op__resume_after_interrupt 0x2
#define __enum_run_op__yield 0x3

#define run_op_ret(a) ((0x000000000000000FULL & a) >> 0)
#define run_op_arg(a) ((0xFFFFFFFFFFFFFFF0ULL & a) >> 4)

static inline vcpuid_t
__run_op(vcpuid_t vcpuid, uint64_t arg1, uint64_t arg2)
{
    return _vmcall(
        __enum_run_op, vcpuid, arg1, arg2
    );
}

// -----------------------------------------------------------------------------
// vCPU Operations
// -----------------------------------------------------------------------------

#define __enum_vcpu_op__create_vcpu 0x100
#define __enum_vcpu_op__run_vcpu 0x101
#define __enum_vcpu_op__kill_vcpu 0x102
#define __enum_vcpu_op__destroy_vcpu 0x103

static inline vcpuid_t
__vcpu_op__create_vcpu(domainid_t domainid)
{
    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__create_vcpu,
        domainid,
        0
    );
}

static inline status_t
__vcpu_op__kill_vcpu(vcpuid_t vcpuid)
{
    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__kill_vcpu,
        vcpuid,
        0
    );
}

static inline status_t
__vcpu_op__destroy_vcpu(vcpuid_t vcpuid)
{
    return _vmcall(
        __enum_vcpu_op,
        __enum_vcpu_op__destroy_vcpu,
        vcpuid,
        0
    );
}

#pragma pack(pop)

#endif
