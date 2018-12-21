#include <bfvmm/hve/arch/intel_x64/exit_handler.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <bfvmm/memory_manager/memory_manager.h>

#include "hve/arch/intel_x64/vtd/vtd_sandbox.h"

#include "hve/arch/intel_x64/vtd/ioapic.h"
#include "hve/arch/intel_x64/vcpu.h"
#include <bfvmm/vcpu/vcpu_manager.h>

namespace vtd_sandbox
{
namespace hidden_bridge
{

using namespace eapis::intel_x64;

gsl::span<uint32_t> g_virtual_pci_config {};

// Initial PCI Configuration space for the emulated device
const uint32_t vendor_device = 0xA2948086;
const uint32_t status_command = 0x00000000;
const uint32_t class_sub_prog_rev = 0x060400f0;
const uint32_t bist_htype_ltimer_clsize = 1U << 16;
const uint32_t bar0 = 0xffffffff;
const uint32_t bar1 = 0xffffffff;
const uint32_t slat_subbus_secbus_primbus = (2U << 8) | (2U << 16);
const uint32_t secstat_iolimit_iobase = 0;
const uint32_t memlimit_membase = 0;
const uint32_t prememlimit_premembase = 0;
const uint32_t pre_mem_base_upper = 0;
const uint32_t pre_mem_limit_upper = 0;
const uint32_t iolimitupper_iobaseupper = 0;
const uint32_t cap_ptr = 0x0;
const uint32_t option_rom = 0x0;
const uint32_t bc_intpin_intline = 0x0;        // Device does not support line based interrupts

const uint32_t cap_offset = cap_ptr / sizeof(uint32_t);

// The physical bus/device/function the emulated device will occupy
uint64_t g_bus = 0;
uint64_t g_device = 0;
uint64_t g_function = 0;

bool
handle_cfc_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info
)
{
    bfignored(vcpu);
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    auto cf8 = ::x64::portio::ind(0xCF8);
    auto reg_number = (cf8 & 0x000000FC) >> 2U;
    auto emulate_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | (g_function << 8U);
    auto next_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | ((g_function + 1) << 8U);

    if ((emulate_addr <= cf8) && (cf8 < next_addr)) {
        bfdebug_nhex(0, "Read from PCI bridge:", reg_number);
        auto emulated_val = g_virtual_pci_config.at(reg_number);
        switch (info.size_of_access) {
            case io_instruction::size_of_access::one_byte:
                emulated_val = emulated_val & 0xFF;
                // bfdebug_subnhex(0, "One byte in emulated from CFC:", emulated_val);
                info.val = emulated_val;
                break;

            case io_instruction::size_of_access::two_byte:
                emulated_val = emulated_val & 0xFFFF;
                // bfdebug_subnhex(0, "Two bytes in emulated from CFC:", emulated_val);
                info.val = emulated_val;
                break;

            default:
                // bfdebug_subnhex(0, "Four bytes in emulated from CFC:", emulated_val);
                info.val = emulated_val;
        }
        info.val = emulated_val;
        return true;
    }

    return false;
}

bool
handle_cfc_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info
)
{
    bfignored(vcpu);
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    auto cf8 = ::x64::portio::ind(0xCF8);
    auto device_addr = cf8 & 0xFFFFFF00;
    auto reg_number = (cf8 & 0x000000FC) >> 2U;
    auto emulate_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | (g_function << 8U);

    if (device_addr == emulate_addr) {
        return true;
    }
    return false;
}

bool
handle_cfd_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info
)
{
    bfignored(vcpu);
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    auto cf8 = ::x64::portio::ind(0xCF8);
    auto reg_number = (cf8 & 0x000000FC) >> 2U;
    auto emulate_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | (g_function << 8U);
    auto next_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | ((g_function + 1) << 8U);

    if ((emulate_addr <= cf8) && (cf8 < next_addr)) {
        bfdebug_nhex(0, "Read from PCI bridge:", reg_number);
        auto emulated_val = (g_virtual_pci_config.at(reg_number)) >> 8;
        switch (info.size_of_access) {
            case io_instruction::size_of_access::one_byte:
                emulated_val = emulated_val & 0xFF;
                // bfdebug_subnhex(0, "One byte in emulated from CFD:", emulated_val);
                break;

            case io_instruction::size_of_access::two_byte:
                emulated_val = emulated_val & 0xFFFF;
                // bfdebug_subnhex(0, "Two byte in emulated from CFD:", emulated_val);
                break;

            default:
                // bfdebug_subnhex(0, "Four byte in emulated from CFD:", emulated_val);
                break;
        }
        info.val = emulated_val;
        return true;
    }

    return false;
}

bool
handle_cfd_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info
)
{
    bfignored(vcpu);
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    return false;
}

bool
handle_cfe_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info
)
{
    bfignored(vcpu);
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    auto cf8 = ::x64::portio::ind(0xCF8);
    auto reg_number = (cf8 & 0x000000FC) >> 2U;
    auto emulate_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | (g_function << 8U);
    auto next_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | ((g_function + 1) << 8U);

    if ((emulate_addr <= cf8) && (cf8 < next_addr)) {
        bfdebug_nhex(0, "Read from PCI bridge:", reg_number);
        auto emulated_val = (g_virtual_pci_config.at(reg_number)) >> 16;
        switch (info.size_of_access) {
            case io_instruction::size_of_access::one_byte:
                emulated_val = emulated_val & 0xFF;
                // bfdebug_subnhex(0, "One byte in emulated from CFE:", emulated_val);
                break;

            case io_instruction::size_of_access::two_byte:
                emulated_val = emulated_val & 0xFFFF;
                // bfdebug_subnhex(0, "Two byte in emulated from CFE:", emulated_val);
                break;

            default:
                // bfdebug_subnhex(0, "Four byte in emulated from CFE:", emulated_val);
                break;
        }
        info.val = emulated_val;
        return true;
    }

    return false;
}

bool
handle_cfe_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info
)
{
    bfignored(vcpu);
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    return false;
}

bool
handle_cff_in(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info
)
{
    bfignored(vcpu);
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    auto cf8 = ::x64::portio::ind(0xCF8);
    auto reg_number = (cf8 & 0x000000FC) >> 2U;
    auto emulate_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | (g_function << 8U);
    auto next_addr = 0x80000000U | (g_bus << 16U) | (g_device << 11U) | ((g_function + 1) << 8U);

    if ((emulate_addr <= cf8) && (cf8 < next_addr)) {
        bfdebug_nhex(0, "Read from PCI bridge:", reg_number);
        auto emulated_val = (g_virtual_pci_config.at(reg_number)) >> 24;
        switch (info.size_of_access) {
            case io_instruction::size_of_access::one_byte:
                emulated_val = emulated_val & 0xFF;
                // bfdebug_subnhex(0, "One byte in emulated from CFF:", emulated_val);
                break;

            case io_instruction::size_of_access::two_byte:
                emulated_val = emulated_val & 0xFFFF;
                // bfdebug_subnhex(0, "Two byte in emulated from CFF:", emulated_val);
                break;

            default:
                // bfdebug_subnhex(0, "Four byte in emulated from CFF:", emulated_val);
                break;
        }
        info.val = emulated_val;
        return true;
    }

    return false;
}

bool
handle_cff_out(
    gsl::not_null<vcpu_t *> vcpu,
    io_instruction_handler::info_t &info
)
{
    bfignored(vcpu);
    namespace io_instruction = vmcs_n::exit_qualification::io_instruction;

    return false;
}

void
enable(
    gsl::not_null<eapis::intel_x64::vcpu *> vcpu,
    uint32_t bus,
    uint32_t device,
    uint32_t function
)
{
    // Make sure there is a real PCI device at the address we want to emulate
    uint32_t address = 0x80000000 | bus << 16 | device << 11 | function << 8;
    ::x64::portio::outd(0xCF8, address);
    auto data = ::x64::portio::ind(0xCFC);
    if(data == 0xFFFFFFFF) {
        bferror_info(0, "Failed to hide PCI bridge,");
        bferror_nhex(0, "A real PCI device must exist at IO address:", address);
        return;
    }

    g_bus = bus;
    g_device = device;
    g_function = function;

    g_virtual_pci_config = gsl::make_span(
        static_cast<uint32_t *>(alloc_page()),
        static_cast<long>(BAREFLANK_PAGE_SIZE / sizeof(uint32_t))
    );

    for(auto &val : g_virtual_pci_config) {
        val = 0xBADC0FFE;
    }

    // Standard configuration space
    g_virtual_pci_config.at(0) = vendor_device;
    g_virtual_pci_config.at(1) = status_command;
    g_virtual_pci_config.at(2) = class_sub_prog_rev;
    g_virtual_pci_config.at(3) = bist_htype_ltimer_clsize;
    g_virtual_pci_config.at(4) = bar0;
    g_virtual_pci_config.at(5) = bar1;
    g_virtual_pci_config.at(6) = 0;
    g_virtual_pci_config.at(7) = 0;
    g_virtual_pci_config.at(8) = 0;
    g_virtual_pci_config.at(9) = 0;
    g_virtual_pci_config.at(10) = 0;
    g_virtual_pci_config.at(11) = 0;
    g_virtual_pci_config.at(12) = 0;
    g_virtual_pci_config.at(13) = 0;
    g_virtual_pci_config.at(14) = 0;
    g_virtual_pci_config.at(15) = 0;

    // -------------------------------------------------------------------------
    // PCI configuration space handlers
    // -------------------------------------------------------------------------
    vcpu->add_io_instruction_handler(
        0xCFC,
        io_instruction_handler::handler_delegate_t::create <handle_cfc_in>(),
        io_instruction_handler::handler_delegate_t::create <handle_cfc_out>()
    );

    vcpu->add_io_instruction_handler(
        0xCFD,
        io_instruction_handler::handler_delegate_t::create <handle_cfd_in>(),
        io_instruction_handler::handler_delegate_t::create <handle_cfd_out>()
    );

    vcpu->add_io_instruction_handler(
        0xCFE,
        io_instruction_handler::handler_delegate_t::create <handle_cfe_in>(),
        io_instruction_handler::handler_delegate_t::create <handle_cfe_out>()
    );

    vcpu->add_io_instruction_handler(
        0xCFF,
        io_instruction_handler::handler_delegate_t::create <handle_cff_in>(),
        io_instruction_handler::handler_delegate_t::create <handle_cff_out>()
    );
}

}
}
