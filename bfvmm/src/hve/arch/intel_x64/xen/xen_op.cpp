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

#include <hve/arch/intel_x64/vcpu.h>

#include <hve/arch/intel_x64/xen/xen.h>
#include <hve/arch/intel_x64/xen/memory.h>
#include <hve/arch/intel_x64/xen/xen_op.h>

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

constexpr auto xen_msr_hypercall_page   = 0xC0000500;
constexpr auto xen_msr_debug_ndec       = 0xC0000600;
constexpr auto xen_msr_debug_nhex       = 0xC0000700;

// -----------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------

#define make_delegate(a,b)                                                                          \
    eapis::intel_x64::a::handler_delegate_t::create<xen_op_handler, &xen_op_handler::b>(this)

#define add_xen_vmcall_handler(a)                                                                   \
    add_vmcall_handler(                                                                             \
        vmcall_handler_delegate(xen_op_handler, a))

#define add_xen_rdmsr_handler(a,b)                                                                  \
    add_rdmsr_handler(                                                                              \
        a, make_delegate(rdmsr_handler, b))

#define add_xen_wrmsr_handler(a,b)                                                                  \
    add_wrmsr_handler(                                                                              \
        a, make_delegate(wrmsr_handler, b))

#define add_xen_cpuid_handler(a,b)                                                                  \
    add_cpuid_handler(                                                                              \
        a, make_delegate(cpuid_handler, b))

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

xen_op_handler::xen_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_xen_cpuid_handler(XEN_CPUID_LEAF(0), xen_cpuid_leaf1_handler);
    vcpu->add_xen_cpuid_handler(XEN_CPUID_LEAF(2), xen_cpuid_leaf3_handler);

    vcpu->add_xen_wrmsr_handler(xen_msr_hypercall_page, xen_hypercall_page_wrmsr_handler);
    vcpu->add_xen_wrmsr_handler(xen_msr_debug_ndec, xen_debug_ndec_wrmsr_handler);
    vcpu->add_xen_wrmsr_handler(xen_msr_debug_nhex, xen_debug_nhex_wrmsr_handler);

    vcpu->add_xen_vmcall_handler(HYPERVISOR_memory_op);
}

bool
xen_op_handler::xen_cpuid_leaf1_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = XEN_CPUID_LEAF(5);
    info.rbx = XEN_CPUID_SIGNATURE_EBX;
    info.rcx = XEN_CPUID_SIGNATURE_ECX;
    info.rdx = XEN_CPUID_SIGNATURE_EDX;

    return true;
}

bool
xen_op_handler::xen_cpuid_leaf3_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    info.rax = 1;
    info.rbx = xen_msr_hypercall_page;
    info.rcx = 0;
    info.rdx = 0;

    return true;
}

static void
vmx_init_hypercall_page(void *hypercall_page)
{
    for (auto i = 0; i < (0x1000 / 32); i++ )
    {
        auto p = (char *)hypercall_page + (i * 32);
        *(uint8_t  *)(p + 0) = 0xb8; /* mov imm32, %eax */
        *(uint32_t *)(p + 1) = i;
        *(uint8_t  *)(p + 5) = 0x0f; /* vmcall */
        *(uint8_t  *)(p + 6) = 0x01;
        *(uint8_t  *)(p + 7) = 0xc1;
        *(uint8_t  *)(p + 8) = 0xc3; /* ret */
    }
}

bool
xen_op_handler::xen_hypercall_page_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    auto map = vcpu_cast(vcpu)->map_gpa_4k<uint8_t>(info.val);
    vmx_init_hypercall_page(map.get());

    return true;
}

bool
xen_op_handler::xen_debug_ndec_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfdebug_ndec(0, "debug", info.val);
    return true;
}

bool
xen_op_handler::xen_debug_nhex_wrmsr_handler(
    gsl::not_null<vcpu_t *> vcpu, eapis::intel_x64::wrmsr_handler::info_t &info)
{
    bfignored(vcpu);

    bfdebug_nhex(0, "debug", info.val);
    return true;
}

bool
xen_op_handler::HYPERVISOR_memory_op(
    gsl::not_null<vcpu_t *> vcpu)
{
    if (vcpu->rax() != __HYPERVISOR_memory_op) {
        return false;
    }

    switch(vcpu->rdi()) {
        case XENMEM_memory_map:
        {
            auto XENMEM_memory_map_delegate =
                guard_vmcall_delegate(xen_op_handler, XENMEM_memory_map_handler);

            return guard_vmcall(vcpu, XENMEM_memory_map_delegate);
        }

        default:
            break;
    };

    throw std::runtime_error("unknown HYPERVISOR_memory_op opcode");
}

uint64_t
xen_op_handler::XENMEM_memory_map_handler(
    gsl::not_null<vcpu_t *> vcpu)
{
    // auto map =
    //     bfvmm::x64::make_unique_map<xen_memory_map>(
    //         static_cast<class vcpu *>(vcpu.get())->gpa_to_hpa(vcpu->rsi())
    //     );

    // bffield_hex(map->nr_entries);
    return 0;
}


}
