//
// Bareflank Hyperkernel
// Copyright (C) 2019 Assured Information Security, Inc.
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

#include <hve/arch/intel_x64/pci.h>
#include <hve/arch/intel_x64/visr.h>
#include <hve/arch/intel_x64/vcpu.h>

using namespace eapis::intel_x64;

namespace vtd {
    uint64_t visr_vector = 0;
    uint64_t ndvm_vector = 0;
    uint64_t ndvm_apic_id = 0;
    uint64_t ndvm_vcpu_id = 0;
}

using namespace hyperkernel::intel_x64;
namespace io = vmcs_n::exit_qualification::io_instruction;

namespace hyperkernel::intel_x64 {

#define add_io_hdlr(port, in, out) m_vcpu->add_io_instruction_handler( \
    port, \
    ::eapis::intel_x64::io_instruction_handler::handler_delegate_t::create<visr, &visr::in>(this), \
    ::eapis::intel_x64::io_instruction_handler::handler_delegate_t::create<visr, &visr::out>(this))

#define emulate_cpuid_leaf(leaf, hdlr) m_vcpu->emulate_cpuid( \
    leaf, \
    ::eapis::intel_x64::cpuid_handler::handler_delegate_t::create<visr, &visr::hdlr>(this))

static void ptio_in(uint32_t port, uint32_t size, uint64_t &val)
{
    switch (size) {
    case io::size_of_access::one_byte:
        val = ::x64::portio::inb(gsl::narrow_cast<uint16_t>(port));
        break;
    case io::size_of_access::two_byte:
        val = ::x64::portio::inw(gsl::narrow_cast<uint16_t>(port));
        break;
    default:
        val = ::x64::portio::ind(gsl::narrow_cast<uint16_t>(port));
    }
}

static void ptio_out(uint32_t port, uint32_t size, uint32_t val)
{
    switch (size) {
    case io::size_of_access::one_byte:
        ::x64::portio::outb(port, gsl::narrow_cast<uint8_t>(val));
        break;
    case io::size_of_access::two_byte:
        ::x64::portio::outw(port, gsl::narrow_cast<uint16_t>(val));
        break;
    default:
        ::x64::portio::outd(port, val);
    }
}

visr::visr(gsl::not_null<vcpu *> vcpu,
           uint32_t bus,
           uint32_t dev,
           uint32_t fun) :
    m_self{bdf_to_cf8(bus, dev, fun)},
    m_next{bdf_to_cf8(bus, dev, fun + 1)},
    m_vcpu{vcpu}
{
    m_cfg[0x0] = dev_ven;
    m_cfg[0x1] = sts_cmd;
    m_cfg[0x2] = class_sub_prog_rev;
    m_cfg[0x3] = bist_hdr_ltimer_clsz;
    m_cfg[0xD] = capptr;

    m_cfg.at(msi_base) = 0x00005;  // MSI Capability ID, end of capabilties
    m_cfg.at(msi_base + 1) = 0x0;  // MSI Address will be written here
    m_cfg.at(msi_base + 2) = 0x0;  // MSI Data will be written here
    m_cfg.at(msi_base + 3) = 0x0;  // Unmask all messages
    m_cfg.at(msi_base + 4) = 0x0;  // Set no pending messages

    // Config handlers
    add_io_hdlr(0xCFC, handle_cfc_in, handle_cfc_out);
    add_io_hdlr(0xCFD, handle_cfd_in, handle_cfd_out);
    add_io_hdlr(0xCFE, handle_cfe_in, handle_cfe_out);
    add_io_hdlr(0xCFF, handle_cff_in, handle_cff_out);

    // Handlers to coordinate interupt injection
    emulate_cpuid_leaf(0xf00dbeef, receive_vector_from_windows);
    emulate_cpuid_leaf(0xcafebabe, forward_interrupt_to_ndvm);
}

bool visr::handle_cfc_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);
    if (!this->self(cf8)) {
        ptio_in(0xCFC, info.size_of_access, info.val);
        return true;
    }

    auto reg = cf8_to_reg(cf8);
    auto emulated_val = m_cfg.at(reg);

    // Pass through BARs and MSI regs
    if(this->bar(reg) || this->msi(reg)) {
        auto cfc = ::x64::portio::ind(0xCFC);
        emulated_val = cfc;
    }

    switch (info.size_of_access) {
    case io::size_of_access::one_byte:
        emulated_val = emulated_val & 0xFF;
        info.val = emulated_val;
        break;

    case io::size_of_access::two_byte:
        emulated_val = emulated_val & 0xFFFF;
        info.val = emulated_val;
        break;

    default:
        info.val = emulated_val;
    }

    return true;
}

bool visr::handle_cfc_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);
    auto reg = cf8_to_reg(cf8);

    if (!this->self(cf8) || (this->msi(reg) || this->bar(reg))) {
        ptio_out(0xCFC, info.size_of_access, info.val);
        return true;
    }

    auto new_val = info.val;
    auto old_val = m_cfg.at(reg);

    switch (info.size_of_access) {
    case io::size_of_access::one_byte:
        new_val = new_val & 0xFF;
        m_cfg.at(reg) = (old_val & 0xFFFFFF00) | new_val;
        break;

    case io::size_of_access::two_byte:
        new_val = new_val & 0xFFFF;
        m_cfg.at(reg) = (old_val & 0xFFFF0000) | new_val;
        break;

    default:
        m_cfg.at(reg) = new_val;
    }

    return true;
}

bool visr::handle_cfd_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);
    if (!this->self(cf8)) {
        ptio_in(0xCFD, info.size_of_access, info.val);
        return true;
    }

    auto reg = cf8_to_reg(cf8);
    auto emulated_val = (m_cfg.at(reg)) >> 8;

    // Pass through BARs and MSI regs
    if (this->bar(reg) || this->msi(reg)) {
        auto cfc = ::x64::portio::ind(0xCFC);
        emulated_val = cfc >> 8;
    }

    switch (info.size_of_access) {
    case io::size_of_access::one_byte:
        emulated_val = emulated_val & 0xFF;
        break;

    case io::size_of_access::two_byte:
        emulated_val = emulated_val & 0xFFFF;
        break;

    default:
        break;
    }

    info.val = emulated_val;
    return true;
}

bool visr::handle_cfd_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    ptio_out(0xCFD, info.size_of_access, info.val);
    return true;
}

bool visr::handle_cfe_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);
    if (!this->self(cf8)) {
        ptio_in(0xCFE, info.size_of_access, info.val);
        return true;
    }

    auto reg = cf8_to_reg(cf8);
    auto emulated_val = (m_cfg.at(reg)) >> 16;

    // Pass through BARs and MSI regs
    if (this->bar(reg) || this->msi(reg)) {
        auto cfc = ::x64::portio::ind(0xCFC);
        emulated_val = cfc >> 16;
    }

    switch (info.size_of_access) {
    case io::size_of_access::one_byte:
        emulated_val = emulated_val & 0xFF;
        break;

    case io::size_of_access::two_byte:
        emulated_val = emulated_val & 0xFFFF;
        break;

    default:
        break;
    }

    info.val = emulated_val;
    return true;
}

bool
visr::handle_cfe_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    ptio_out(0xCFE, info.size_of_access, info.val);
    return true;
}

bool
visr::handle_cff_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);
    if (!this->self(cf8)) {
        ptio_in(0xCFF, info.size_of_access, info.val);
        return true;
    }

    auto reg = cf8_to_reg(cf8);
    auto emulated_val = (m_cfg.at(reg)) >> 24;

    // Pass through BARs and MSI regs
    if (this->bar(reg) || this->msi(reg)) {
        auto cfc = ::x64::portio::ind(0xCFC);
        emulated_val = cfc >> 24;
    }

    ensures(info.size_of_access == io::size_of_access::one_byte);
    info.val = emulated_val;

    return true;
}

bool visr::handle_cff_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    ptio_out(0xCFF, info.size_of_access, info.val);
    return true;
}

static bool need_injection = false;

bool visr::receive_vector_from_windows(
    gsl::not_null<vcpu_t *> vcpu,
    cpuid_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    using namespace ::intel_x64::msrs;

    auto msr = ia32_apic_base::get();
    expects(ia32_apic_base::state::get(msr) == ia32_apic_base::state::xapic);

    vtd::visr_vector = m_vcpu->rcx();
    bfdebug_nhex(0, "Recieved vector from VISR driver:", vtd::visr_vector);

    auto hpa = ::intel_x64::msrs::ia32_apic_base::apic_base::get(msr);
    auto ptr = vcpu_cast(vcpu)->map_hpa_4k<uint8_t>(hpa);
    auto reg = *reinterpret_cast<uint32_t *>(ptr.get() + 0x20);
    auto id = reg >> 24;

    vtd::ndvm_apic_id = id;

    return true;
}

bool visr::forward_interrupt_to_ndvm(
    gsl::not_null<vcpu_t *> vcpu,
    cpuid_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    // There is a race between when the NDVM is destroyed from the g_vcm's
    // perspective and when an in-flight interrupt arrives to visr. There is no
    // way to prevent this with a hard Ctrl-C from dom0, so it is possible we
    // get here and the NDVM is already dead.

    try {
        auto ndvm_vcpu = reinterpret_cast<hyperkernel::intel_x64::vcpu *>(
                get_vcpu(vtd::ndvm_vcpu_id).get());

        ndvm_vcpu->queue_external_interrupt(vtd::ndvm_vector, false);
    } catch (std::runtime_error &e) {
        ;
    }

    return true;
}

}
