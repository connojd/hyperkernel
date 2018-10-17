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

#ifndef XEN_OP_INTEL_X64_HYPERKERNEL_H
#define XEN_OP_INTEL_X64_HYPERKERNEL_H

#include "cpuid.h"
#include "../base.h"

#include <eapis/hve/arch/intel_x64/vmexit/cpuid.h>
#include <eapis/hve/arch/intel_x64/vmexit/wrmsr.h>
#include <eapis/hve/arch/intel_x64/vmexit/rdmsr.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HYPERKERNEL_HVE
#ifdef SHARED_HYPERKERNEL_HVE
#define EXPORT_HYPERKERNEL_HVE EXPORT_SYM
#else
#define EXPORT_HYPERKERNEL_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HYPERKERNEL_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class vcpu;

class EXPORT_HYPERKERNEL_HVE xen_op_handler
{
public:

    xen_op_handler(
        gsl::not_null<vcpu *> vcpu);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~xen_op_handler() = default;

private:

    bool HYPERVISOR_memory_op(gsl::not_null<vcpu_t *> vcpu);
    uint64_t XENMEM_memory_map_handler(gsl::not_null<vcpu_t *> vcpu);

    bool xen_cpuid_leaf1_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);
    bool xen_cpuid_leaf3_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info);

    bool xen_hypercall_page_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);
    bool xen_debug_ndec_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);
    bool xen_debug_nhex_wrmsr_handler(
        gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info);

private:

    vcpu *m_vcpu;
    uint64_t m_hypercall_page_gpa{0};

public:

    /// @cond

    xen_op_handler(xen_op_handler &&) = default;
    xen_op_handler &operator=(xen_op_handler &&) = default;

    xen_op_handler(const xen_op_handler &) = delete;
    xen_op_handler &operator=(const xen_op_handler &) = delete;

    /// @endcond
};

}

#endif
