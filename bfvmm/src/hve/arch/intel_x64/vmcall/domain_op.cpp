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
#include <hve/arch/intel_x64/vmcall/domain_op.h>

namespace hyperkernel::intel_x64
{

vmcall_domain_op_handler::vmcall_domain_op_handler(
    gsl::not_null<vcpu *> vcpu
) :
    m_vcpu{vcpu}
{
    using namespace vmcs_n;

    vcpu->add_vmcall_handler(
        vmcall_handler_delegate(vmcall_domain_op_handler, dispatch)
    );
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

uintptr_t ndvm_page_hpa{0};
eapis::x64::unique_map<uint8_t> ndvm_page_ump;

void
vmcall_domain_op_handler::domain_op__ndvm_share_page(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        auto [hpa, unused] = vcpu->gva_to_hpa(vcpu->rcx());

        ndvm_page_ump = vcpu->map_hpa_4k<uint8_t>(hpa);
        ndvm_page_hpa = hpa;

        bfdebug_nhex(0, "NDVM page gva: ", vcpu->rcx());
        bfdebug_nhex(0, "NDVM page hpa: ", hpa);

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}

void
vmcall_domain_op_handler::domain_op__remap_to_ndvm_page(
    gsl::not_null<vcpu *> vcpu)
{
    try {
        expects(ndvm_page_hpa != 0);

        const auto [gpa, unused] = vcpu->gva_to_gpa(vcpu->rcx());
        const auto gpa_2m = bfn::upper(gpa, 21);
        const auto gpa_4k = bfn::upper(gpa, 12);
        expects(gpa_4k == gpa);

        vcpu->dom()->unmap(gpa_2m);

        for (auto p = gpa_2m; p < gpa_4k; p += 4096) {
            vcpu->dom()->map_4k_rwe(p, p);
        }

        vcpu->dom()->map_4k_rw(gpa_4k, (uintptr_t)ndvm_page_hpa);

        for (auto p = gpa_4k + 4096; p < gpa_2m + (1UL << 21); p += 4096) {
            vcpu->dom()->map_4k_rwe(p, p);
        }

        bfdebug_nhex(0, "Dom0 shm gpa_2m: ", gpa_2m);
        bfdebug_nhex(0, "Dom0 shm gpa_4k: ", gpa);
        bfdebug_subnhex(0, "remapped to hpa: ", ndvm_page_hpa);

        ::intel_x64::vmx::invept_global();

        vcpu->set_rax(SUCCESS);
    }
    catchall({
        vcpu->set_rax(FAILURE);
    })
}


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
        get_domain(vcpu->rcx())->set_ndvm_status(vcpu->rdx());
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

        case __enum_domain_op__remap_to_ndvm_page:
            this->domain_op__remap_to_ndvm_page(vcpu);
            return true;

        case __enum_domain_op__set_ndvm_status:
            this->domain_op__set_ndvm_status(vcpu);
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

        default:
            break;
    };

    throw std::runtime_error("unknown domain opcode");
}

}
