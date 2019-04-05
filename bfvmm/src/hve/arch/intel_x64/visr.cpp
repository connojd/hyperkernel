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

//namespace vtd {
//    uint64_t ndvm_vector = 0;
//    uint64_t ndvm_apic_id = 0;
//    uint64_t ndvm_vcpu_id = 0;
//}

using namespace hyperkernel::intel_x64;
namespace io = vmcs_n::exit_qualification::io_instruction;

namespace hyperkernel::intel_x64 {

#define add_io_hdlr(port, in, out) vcpu->add_io_instruction_handler( \
    port, \
    ::eapis::intel_x64::io_instruction_handler::handler_delegate_t::create<visr, &visr::in>(this), \
    ::eapis::intel_x64::io_instruction_handler::handler_delegate_t::create<visr, &visr::out>(this))

#define emulate_cpuid_leaf(leaf, hdlr) vcpu->emulate_cpuid( \
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

visr *visr::instance() noexcept
{
    static visr self;
    return &self;
}

void visr::add_dev(uint32_t bus, uint32_t dev, uint32_t fun)
{
    auto pdev = std::make_unique<struct pci_dev>(bus, dev, fun);

    for (auto i = 0; i < 64; i++) {
        pdev->set_reg(i, 0);
    }

    pdev->set_reg(0x0, dev_ven);
    pdev->set_reg(0x1, sts_cmd);
    pdev->set_reg(0x2, class_sub_prog_rev);
    pdev->set_reg(0x3, bist_hdr_ltimer_clsz);
    pdev->set_reg(0xD, capptr);
    pdev->set_reg(0xF, maxlat_mingnt_pin_line);
    pdev->set_reg(msi_base, 0x00005);  // MSI Capability ID, end of capabilties

    m_devs[bdf_to_cf8(bus, dev, fun)] = std::move(pdev);
}

void visr::enable(gsl::not_null<vcpu *> vcpu)
{
    add_io_hdlr(0xCFC, handle_cfc_in, handle_cfc_out);
    add_io_hdlr(0xCFD, handle_cfd_in, handle_cfd_out);
    add_io_hdlr(0xCFE, handle_cfe_in, handle_cfe_out);
    add_io_hdlr(0xCFF, handle_cff_in, handle_cff_out);

    emulate_cpuid_leaf(0xf00dbeef, receive_vector_from_windows);
    emulate_cpuid_leaf(0xcafebabe, forward_interrupt_to_ndvm);
}

bool visr::is_emulating(uint32_t cf8) const
{
    return m_devs.count(cf8 & ~0xFFUL) != 0;
}

bool visr::handle_cfc_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    const auto cf8 = ::x64::portio::ind(0xCF8);
    if (!this->is_emulating(cf8)) {
        ptio_in(0xCFC, info.size_of_access, info.val);
        return true;
    }

    //printf("i:cfc:%lu @ %02x:%02x:%02x:%02x - ", info.size_of_access + 1, cf8_to_bus(cf8), cf8_to_dev(cf8), cf8_to_fun(cf8), cf8_to_reg(cf8));

    auto *dev = m_devs[cf8 & ~0xFFUL].get();
    auto reg = cf8_to_reg(cf8);
    auto emulated_val = dev->reg(reg);

    // Pass through BARs and MSI regs
    if(dev->is_bar(reg) || dev->is_msi(reg)) {
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

    //printf("%08lx\n", info.val);

    return true;
}

bool visr::handle_cfc_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);
    if (!this->is_emulating(cf8)) {
        ptio_out(0xCFC, info.size_of_access, info.val);
        return true;
    }

    auto *dev = m_devs[cf8 & ~0xFFUL].get();
    auto reg = cf8_to_reg(cf8);

    if (dev->is_msi(reg) || dev->is_bar(reg)) {
        ptio_out(0xCFC, info.size_of_access, info.val);
        return true;
    }

    //auto new_val = info.val;
    //auto old_val = dev->reg(reg);

    //switch (info.size_of_access) {
    //case io::size_of_access::one_byte:
    //    new_val = new_val & 0xFF;
    //    dev->set_reg(reg, (old_val & 0xFFFFFF00) | new_val);
    //    break;

    //case io::size_of_access::two_byte:
    //    new_val = new_val & 0xFFFF;
    //    dev->set_reg(reg, (old_val & 0xFFFF0000) | new_val);
    //    break;

    //default:
    //    dev->set_reg(reg, new_val);
    //}

    return true;
}

bool visr::handle_cfd_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);

    if (!this->is_emulating(cf8)) {
        ptio_in(0xCFD, info.size_of_access, info.val);
        return true;
    }

    //printf("i:cfd:%lu @ %02x:%02x:%02x:%02x - ", info.size_of_access + 1, cf8_to_bus(cf8), cf8_to_dev(cf8), cf8_to_fun(cf8), cf8_to_reg(cf8));

    auto *dev = m_devs[cf8 & ~0xFFUL].get();
    auto reg = cf8_to_reg(cf8);
    auto emulated_val = (dev->reg(reg)) >> 8;

    // Pass through BARs and MSI regs
    if (dev->is_bar(reg) || dev->is_msi(reg)) {
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
        throw std::runtime_error("cfd in:invalid size");
        break;
    }

    info.val = emulated_val;
    //printf("%08lx\n", info.val);
    return true;
}

bool visr::handle_cfd_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);

    if (!this->is_emulating(cf8)) {
        ptio_out(0xCFD, info.size_of_access, info.val);
        return true;
    }

    auto *dev = m_devs[cf8 & ~0xFFUL].get();
    auto reg = cf8_to_reg(cf8);

    if (dev->is_bar(reg) || dev->is_msi(reg)) {
        ptio_out(0xCFD, info.size_of_access, info.val);
        return true;
    }

    return true;
}

bool visr::handle_cfe_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);

    if (!this->is_emulating(cf8)) {
        ptio_in(0xCFE, info.size_of_access, info.val);
        return true;
    }

    //printf("i:cfe:%lu @ %02x:%02x:%02x:%02x - ", info.size_of_access + 1, cf8_to_bus(cf8), cf8_to_dev(cf8), cf8_to_fun(cf8), cf8_to_reg(cf8));

    auto *dev = m_devs[cf8 & ~0xFFUL].get();
    auto reg = cf8_to_reg(cf8);
    auto emulated_val = (dev->reg(reg)) >> 16;

    // Pass through BARs and MSI regs
    if (dev->is_bar(reg) || dev->is_msi(reg)) {
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
        throw std::runtime_error("cfe in:invalid size");
        break;
    }

    info.val = emulated_val;
    //printf("%08lx\n", info.val);
    return true;
}

bool
visr::handle_cfe_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);

    if (!this->is_emulating(cf8)) {
        ptio_out(0xCFE, info.size_of_access, info.val);
        return true;
    }

    auto *dev = m_devs[cf8 & ~0xFFUL].get();
    auto reg = cf8_to_reg(cf8);

    if (dev->is_bar(reg) || dev->is_msi(reg)) {
        ptio_out(0xCFE, info.size_of_access, info.val);
        return true;
    }

    return true;
}

bool
visr::handle_cff_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);

    if (!this->is_emulating(cf8)) {
        ptio_in(0xCFF, info.size_of_access, info.val);
        return true;
    }

    //printf("i:cff:%lu @ %02x:%02x:%02x:%02x - ", info.size_of_access + 1, cf8_to_bus(cf8), cf8_to_dev(cf8), cf8_to_fun(cf8), cf8_to_reg(cf8));

    auto *dev = m_devs[cf8 & ~0xFFUL].get();
    auto reg = cf8_to_reg(cf8);
    auto emulated_val = (dev->reg(reg)) >> 24;

    // Pass through BARs and MSI regs
    if (dev->is_bar(reg) || dev->is_msi(reg)) {
        auto cfc = ::x64::portio::ind(0xCFC);
        emulated_val = cfc >> 24;
    }

    ensures(info.size_of_access == io::size_of_access::one_byte);
    info.val = emulated_val;
    //printf("%08lx\n", info.val);

    return true;
}

bool visr::handle_cff_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info)
{
    bfignored(vcpu);

    auto cf8 = ::x64::portio::ind(0xCF8);

    if (!this->is_emulating(cf8)) {
        ptio_out(0xCFF, info.size_of_access, info.val);
        return true;
    }

    auto *dev = m_devs[cf8 & ~0xFFUL].get();
    auto reg = cf8_to_reg(cf8);

    if (dev->is_bar(reg) || dev->is_msi(reg)) {
        ptio_out(0xCFF, info.size_of_access, info.val);
        return true;
    }

    return true;
}

void visr::stash_phys_vector(uint32_t vec)
{
    expects(vec >= 32);
    expects(vec <= 255);

    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto &p : m_devs) {
        auto dev = p.second.get();
        if (dev->phys_vec() == 0) {
            dev->set_phys_vec(vec);
            bfdebug_nhex(0, "Stashed vector", vec);
            break;
        }
    }
}

uint32_t visr::bind_phys_vector(uint64_t vcpuid)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto &p : m_devs) {
        auto dev = p.second.get();
        if (dev->phys_vec() != 0 && dev->vcpuid() == INVALID_VCPUID) {
            dev->set_vcpuid(vcpuid);
            return dev->phys_vec();
        }
    }

    bferror_info(0, "bind_phys_vector failed");
    return 0;
}

void visr::bind_virt_vector(uint64_t vcpuid, uint32_t virt)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    for (auto &p : m_devs) {
        auto dev = p.second.get();
        if (dev->vcpuid() == vcpuid) {
            dev->set_virt_vec(virt);
            m_vector_map[dev->phys_vec()] = dev;
            return;
        }
    }

    throw std::invalid_argument("visr: invalid vcpuid");
}

bool visr::deliver(vcpu *vcpu, uint32_t vec)
{
    expects(vcpu->is_domU());

    auto itr = m_vector_map.find(vec);
    if (itr == m_vector_map.end()) {
        // Return unmapped vectors to the host
        return false;
    }

    // There is a race between when the NDVM is destroyed from the g_vcm's
    // perspective and when an in-flight interrupt arrives to visr. There is no
    // way to prevent this with a hard Ctrl-C from dom0, so it is possible we
    // get here and the NDVM is already dead.

    try {
        auto dev = itr->second;
        auto ndvm = get_vcpu(dev->vcpuid()).get();
        bool inject_now = vcpu->dom()->is_ndvm();
        ndvm->queue_external_interrupt(dev->virt_vec(), inject_now);
    } catch (std::runtime_error &re) {
        ;
    }

    return true;
}

bool visr::receive_vector_from_windows(
    gsl::not_null<vcpu_t *> vcpu,
    cpuid_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    using namespace ::intel_x64::msrs;

    auto msr = ia32_apic_base::get();
    expects(ia32_apic_base::state::get(msr) == ia32_apic_base::state::xapic);

    auto vec = vcpu->rcx();
    expects(vec != 0);
    bfdebug_nhex(0, "Recieved vector from VISR driver:", vec);

    /// Find a device that doesn't have a vector yet and assign vec to it
    ///
    this->stash_phys_vector(vec);

//    auto hpa = ::intel_x64::msrs::ia32_apic_base::apic_base::get(msr);
//    auto ptr = vcpu_cast(vcpu)->map_hpa_4k<uint8_t>(hpa);
//    auto reg = *reinterpret_cast<uint32_t *>(ptr.get() + 0x20);
//    auto id = reg >> 24;

//    vtd::ndvm_apic_id = id;

    return true;
}

// RCX contains the phys vector to forward
bool visr::forward_interrupt_to_ndvm(
    gsl::not_null<vcpu_t *> vcpu,
    cpuid_handler::info_t &info)
{
    bfignored(vcpu);

    // There is a race between when the NDVM is destroyed from the g_vcm's
    // perspective and when an in-flight interrupt arrives to visr. There is no
    // way to prevent this with a hard Ctrl-C from dom0, so it is possible we
    // get here and the NDVM is already dead.

//
//    bfdebug_subnhex(0, "rax", info.rax);
//    bfdebug_subnhex(0, "rbx", info.rbx);
//    bfdebug_subnhex(0, "rcx", info.rcx);
//    bfdebug_subnhex(0, "rdx", info.rdx);
//
    try {
//        bfdebug_nhex(0, "visr: forwarding vector:", info.rcx);
        auto dev = m_vector_map.at(info.rcx);
        auto ndvm = get_vcpu(dev->vcpuid()).get();
        expects(ndvm->dom()->is_ndvm());
        ndvm->queue_external_interrupt(dev->virt_vec(), false);
    } catch (std::runtime_error &e) {
        ;
    }

    return true;
}

}
