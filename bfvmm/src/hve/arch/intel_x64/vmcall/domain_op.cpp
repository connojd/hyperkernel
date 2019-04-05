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

#include <iostream>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/iommu.h>
#include <hve/arch/intel_x64/vmcall/domain_op.h>
#include <bfvmm/memory_manager/arch/x64/cr3.h>

namespace hyperkernel::intel_x64
{

uintptr_t write_queue_fva{};
uintptr_t write_mutex_fva{};
uintptr_t write_queue_nva{};
uintptr_t write_mutex_nva{};
uintptr_t write_queue_hpa{};
uintptr_t write_mutex_hpa{};

uintptr_t read_queue_fva{};
uintptr_t read_mutex_fva{};
uintptr_t read_queue_nva{};
uintptr_t read_mutex_nva{};
uintptr_t read_queue_hpa{};
uintptr_t read_mutex_hpa{};

eapis::x64::unique_map<uint32_t> g_xapic_map{nullptr};

void vmcall_domain_op_handler::signal_shootdown()
{
    uint32_t val = (3UL << 18) | // all excl. self
                   (1UL << 14) | // Level assert
                   (4UL << 8)  | // NMI delivery mode
                   2;            // NMI vector

    uint32_t *icr = (uint32_t *)((uintptr_t)g_xapic_map.get() + 0x300);
    *icr = val;

    ::intel_x64::barrier::mb();
}

vmcall_domain_op_handler::vmcall_domain_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_domain_op_handler, dispatch)
    );

//    if (!g_xapic_map) {
//        auto msr = ::intel_x64::msrs::ia32_apic_base::get();
//        auto hpa = ::intel_x64::msrs::ia32_apic_base::apic_base::get(msr);
//        expects(hpa == 0xFEE00000);
//
//        auto hva = g_mm->alloc_map(4096);
//
//        g_cr3->map_4k(hva,
//                      hpa,
//                      bfvmm::x64::cr3::mmap::attr_type::read_write,
//                      bfvmm::x64::cr3::mmap::memory_type::uncacheable);
//
//        g_xapic_map = eapis::x64::unique_map<uint32_t>(
//            static_cast<uint32_t *>(hva),
//            eapis::x64::unmapper(hva, 4096)
//        );
//    }
}

void
vmcall_domain_op_handler::domain_op__create_domain(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        vcpu->set_rax(domain::generate_domainid());
        g_dm->create(vcpu->rax(), nullptr);
    }
    catchall({
        vcpu->set_rax(INVALID_DOMAINID);
    })
}

void
vmcall_domain_op_handler::domain_op__destroy_domain(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rcx() == self) {
            throw std::runtime_error(
                "domain_op__destroy_domain: self not supported");
        }

        g_dm->destroy(vcpu->rcx(), nullptr);
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__share_page(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto args =
            vcpu->map_arg<__domain_op__share_page_arg_t>(vcpu->rcx());

        if (args->foreign_domainid == self) {
            throw std::runtime_error(
                "domain_op__share_page: self not supported");
        }

        auto [hpa, unused] =
            vcpu->gpa_to_hpa(args->self_gpa);

        switch(args->type) {
            case MAP_RO:
                get_domain(args->foreign_domainid)->map_4k_ro(
                    args->foreign_gpa, hpa
                );
                break;

            case MAP_RW:
                get_domain(args->foreign_domainid)->map_4k_rw(
                    args->foreign_gpa, hpa
                );
                break;

            case MAP_RWE:
                get_domain(args->foreign_domainid)->map_4k_rwe(
                    args->foreign_gpa, hpa
                );
                break;

            default:
                throw std::runtime_error("unknown map type");
        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__add_e820_entry(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto args =
            vcpu->map_arg<__domain_op__add_e820_entry_arg_t>(vcpu->rcx());

        get_domain(args->domainid)->add_e820_entry({
            args->addr, args->size, args->type
        });

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

std::unordered_map<uintptr_t, uintptr_t> ndvm_data;

void
vmcall_domain_op_handler::domain_op__ndvm_share_page(
    gsl::not_null<vcpu *> vcpu)
{
    try {
//        auto [hpa, unused] = vcpu->gva_to_hpa(vcpu->rcx());
//        ndvm_data[vcpu->rcx()] = hpa;
//
//        bfdebug_nhex(0, "share page gva: ", vcpu->rcx());
//        bfdebug_nhex(0, "share page hpa: ", hpa);

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        bfdebug_info(0, "sharing page...failed");
        vcpu->set_rax(FAILURE);
    })
}

//void
//vmcall_domain_op_handler::domain_op__ndvm_rm_page(
//    gsl::not_null<vcpu *> vcpu)
//{
//    ndvm_data.erase(vcpu->rcx());
//}

//bool shootdown_wait()
//{
//    int wait = 0;
//
//    for (auto i = 0; i < shootdown_ready.size(); i++) {
//        wait |= !shootdown_ready[i];
//    }
//
//    return wait != 0;
//}
//
//void shootdown_reset()
//{
//    for (auto i = 0; i < shootdown_ready.size(); i++) {
//        shootdown_ready[i] = false;
//    }
//
//    shootdown_on = false;
//}

uintptr_t access_hpa = 0;
bool filter_ready alignas(64) = false;
bool filter_done alignas(64) = false;

void
vmcall_domain_op_handler::domain_op__access_ndvm_page(
    gsl::not_null<vcpu *> vcpu)
{
    access_hpa = vcpu->gva_to_hpa(vcpu->rcx()).first;
    ensures(access_hpa != 0);
    filter_done = false;
    ::intel_x64::barrier::wmb();
    filter_ready = true;

    ::x64::cache::clflush(&filter_ready);

//    bfdebug_info(0, "access wait");

    while (!filter_done) {
        ::intel_x64::pause();
    }

//    bfdebug_info(0, "access resume");
}

static uintptr_t filter_gpa = 0;
static uintptr_t filter_hpa = 0;

void
vmcall_domain_op_handler::domain_op__filter_done(
    gsl::not_null<vcpu *> vcpu)
{
    vcpu->dom()->unmap(filter_gpa);
    vcpu->dom()->map_4k_rw(filter_gpa, filter_hpa);
    ::intel_x64::vmx::invept_global();

    access_hpa = 0;
//    bfdebug_info(0, "filter done");
//
    ::intel_x64::barrier::wmb();
    filter_done = true;
    ::x64::cache::clflush(&filter_done);

    filter_ready = false;
    ::x64::cache::clflush(&filter_ready);

    return;
}

void
vmcall_domain_op_handler::domain_op__filter_page(
    gsl::not_null<vcpu *> vcpu)
{
    filter_gpa = vcpu->gva_to_gpa(vcpu->rcx()).first;
    filter_hpa = vcpu->gpa_to_hpa(filter_gpa).first;

    ensures(filter_gpa);
    ensures(filter_hpa);

    expects(access_hpa != 0);

    vcpu->dom()->unmap(filter_gpa);
    vcpu->dom()->map_4k_rw(filter_gpa, access_hpa);
    ::intel_x64::vmx::invept_global();
}

void
vmcall_domain_op_handler::domain_op__map_write_queue(gsl::not_null<vcpu *> vcpu)
{
    write_queue_nva = vcpu->rcx();
    write_mutex_nva = vcpu->rdx();

    write_queue_hpa = vcpu->gva_to_hpa(write_queue_nva).first;
    write_mutex_hpa = vcpu->gva_to_hpa(write_mutex_nva).first;

    vcpu->set_rax(SUCCESS);
}

void
vmcall_domain_op_handler::domain_op__map_read_queue(gsl::not_null<vcpu *> vcpu)
{
    read_queue_nva = vcpu->rcx();
    read_mutex_nva = vcpu->rdx();

    read_queue_hpa = vcpu->gva_to_hpa(read_queue_nva).first;
    read_mutex_hpa = vcpu->gva_to_hpa(read_mutex_nva).first;

    vcpu->set_rax(SUCCESS);
}

void
vmcall_domain_op_handler::domain_op__set_write_queue(gsl::not_null<vcpu *> vcpu)
{
    expects(write_queue_hpa);
    expects(write_mutex_hpa);

    write_queue_fva = vcpu->rcx();
    write_mutex_fva = vcpu->rdx();

    const auto [queue_gpa, ign0] = vcpu->gva_to_gpa(write_queue_fva);
    const auto [mutex_gpa, ign1] = vcpu->gva_to_gpa(write_mutex_fva);

    vcpu->dom()->unmap(queue_gpa);
    vcpu->dom()->unmap(mutex_gpa);

    vcpu->dom()->map_4k_rw(queue_gpa, write_queue_hpa);
    vcpu->dom()->map_4k_rw(mutex_gpa, write_mutex_hpa);

    ::intel_x64::vmx::invept_global();
}

void
vmcall_domain_op_handler::domain_op__set_read_queue(gsl::not_null<vcpu *> vcpu)
{
    expects(read_queue_hpa);
    expects(read_mutex_hpa);

    read_queue_fva = vcpu->rcx();
    read_mutex_fva = vcpu->rdx();

    const auto [queue_gpa, ign0] = vcpu->gva_to_gpa(read_queue_fva);
    const auto [mutex_gpa, ign1] = vcpu->gva_to_gpa(read_mutex_fva);

    vcpu->dom()->unmap(queue_gpa);
    vcpu->dom()->unmap(mutex_gpa);

    vcpu->dom()->map_4k_rw(queue_gpa, read_queue_hpa);
    vcpu->dom()->map_4k_rw(mutex_gpa, read_mutex_hpa);

    ::intel_x64::vmx::invept_global();
}

void
vmcall_domain_op_handler::domain_op__lock_acquired(gsl::not_null<vcpu *> vcpu)
{
    bfdebug_nhex(0, "lock acquired", vcpu->id());
}


//    try {
//
//        const auto [gpa, unused] = vcpu->gva_to_gpa(vcpu->rcx());
//        const auto gpa_2m = bfn::upper(gpa, 21);
//        const auto gpa_4k = bfn::upper(gpa, 12);
//
//        expects(gpa_4k == gpa);
//
//        // This is setup for a one-time shootdown, which should be fine for
//        // now because it is only needed when the read thread in the NDVM is
//        // running
//        //
//        // In general this function isn't correct; we are abusing the fact
//        // that Windows only uses NMIs for watchdogs and reboots. So any NMI
//        // signal is a shootdown signal.
//
//        if (vcpu->domid() == 0) {
//            ept_ready = false;
//            shootdown_on = true;
//            ::intel_x64::barrier::mb();
//
//            this->signal_shootdown();
//            while (shootdown_wait()) {
//                ::intel_x64::pause();
//            }
//
//            shootdown_reset();
//
//            // At this point everybody is in the VMM waiting on
//            // !ept_ready, so it is safe to modify the map
//
//            vcpu->dom()->unmap(gpa_2m);
//
//            for (auto p = gpa_2m; p < gpa_4k; p += 4096) {
//                vcpu->dom()->map_4k_rwe(p, p);
//            }
//
//            vcpu->dom()->map_4k_rw(gpa_4k, ndvm_page_hpa);
//
//            for (auto p = gpa_4k + 4096; p < gpa_2m + (1UL << 21); p += 4096) {
//                vcpu->dom()->map_4k_rwe(p, p);
//            }
//
//            ::intel_x64::vmx::invept_global();
//            invalid_eptp = vcpu->dom()->ept().eptp();
//            ::intel_x64::barrier::mb();
//            ept_ready = true;
//
//        } else {
//            vcpu->dom()->unmap(gpa_4k);
//            vcpu->dom()->map_4k_rw(gpa_4k, ndvm_page_hpa);
//            ::intel_x64::vmx::invept_global();
//        }
//
//        vcpu->set_rax(SUCCESS);
//    }
//    catchall({
//        vcpu->set_rax(FAILURE);
//    })
//}


void
vmcall_domain_op_handler::domain_op__set_entry(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rcx() == self) {
            throw std::runtime_error(
                "domain_op__set_entry: self not supported");
        }

        get_domain(vcpu->rcx())->set_entry(vcpu->rdx());
        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__set_uart(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rcx() == self) {
            throw std::runtime_error(
                "domain_op__set_uart: self not supported");
        }

        get_domain(vcpu->rcx())->set_uart(
            gsl::narrow_cast<uart::port_type>(vcpu->rdx())
        );

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__set_pt_uart(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        if (vcpu->rcx() == self) {
            throw std::runtime_error(
                "domain_op__set_pt_uart: self not supported");
        }

        get_domain(vcpu->rcx())->set_pt_uart(
            gsl::narrow_cast<uart::port_type>(vcpu->rdx())
        );

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__dump_uart(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto buffer =
            vcpu->map_gva_4k<char>(vcpu->rdx(), UART_MAX_BUFFER);

        auto bytes_transferred =
            get_domain(vcpu->rcx())->dump_uart(
                gsl::span(buffer.get(), UART_MAX_BUFFER)
            );

        vcpu->set_rax(bytes_transferred);
    }
    catchall({
        vcpu->set_rax(0);
    })
}

void
vmcall_domain_op_handler::domain_op__set_ndvm_status(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto dom = get_domain(vcpu->rcx());
        dom->set_ndvm_status(vcpu->rdx());

////        if (dom->is_ndvm()) {
////            dom->enable_dma_remapping();
////        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__set_ndvm_bus(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto dom = get_domain(vcpu->rcx());

        if (dom->is_ndvm()) {
            bfdebug_nhex(0, "domain_op: NDVM bus:", vcpu->rdx());
            dom->set_ndvm_bus(vcpu->rdx());

            g_iommu->add_domain(dom->id(), dom->ept().eptp());
            g_iommu->map(dom->id(), dom->ndvm_bus(), devfn(0, 0));

            static bool iommu_enabled = false;
            if (!iommu_enabled) {
                g_iommu->enable();
                iommu_enabled = true;
            }
        }

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

bool
vmcall_domain_op_handler::dispatch(
    gsl::not_null<vcpu *> vcpu)
{
    if (vcpu->rax() != __enum_domain_op) {
        return false;
    }

    switch(vcpu->rbx()) {
        case __enum_domain_op__create_domain:
            this->domain_op__create_domain(vcpu);
            return true;

        case __enum_domain_op__destroy_domain:
            this->domain_op__destroy_domain(vcpu);
            return true;

        case __enum_domain_op__share_page:
            this->domain_op__share_page(vcpu);
            return true;

        case __enum_domain_op__ndvm_share_page:
            this->domain_op__ndvm_share_page(vcpu);
            return true;

        case __enum_domain_op__access_ndvm_page:
            this->domain_op__access_ndvm_page(vcpu);
            return true;

        case __enum_domain_op__filter_page:
            this->domain_op__filter_page(vcpu);
            return true;

        case __enum_domain_op__filter_done:
            this->domain_op__filter_done(vcpu);
            return true;

        case __enum_domain_op__map_write_queue:
            this->domain_op__map_write_queue(vcpu);
            return true;

        case __enum_domain_op__map_read_queue:
            this->domain_op__map_read_queue(vcpu);
            return true;

        case __enum_domain_op__set_write_queue:
            this->domain_op__set_write_queue(vcpu);
            return true;

        case __enum_domain_op__set_read_queue:
            this->domain_op__set_read_queue(vcpu);
            return true;

        case __enum_domain_op__set_ndvm_status:
            this->domain_op__set_ndvm_status(vcpu);
            return true;

        case __enum_domain_op__set_ndvm_bus:
            this->domain_op__set_ndvm_bus(vcpu);
            return true;

        case __enum_domain_op__add_e820_entry:
            this->domain_op__add_e820_entry(vcpu);
            return true;

        case __enum_domain_op__set_entry:
            this->domain_op__set_entry(vcpu);
            return true;

        case __enum_domain_op__set_uart:
            this->domain_op__set_uart(vcpu);
            return true;

        case __enum_domain_op__set_pt_uart:
            this->domain_op__set_pt_uart(vcpu);
            return true;

        case __enum_domain_op__dump_uart:
            this->domain_op__dump_uart(vcpu);
            return true;

        case __enum_domain_op__lock_acquired:
            this->domain_op__lock_acquired(vcpu);
            return true;

        default:
            break;
    };

    throw std::runtime_error("unknown domain opcode");
}

}
