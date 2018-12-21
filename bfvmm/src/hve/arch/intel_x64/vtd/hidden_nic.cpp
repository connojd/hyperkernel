#include <bfvmm/hve/arch/intel_x64/exit_handler.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>

#include "hve/arch/intel_x64/vtd/vtd_sandbox.h"

namespace vtd_sandbox
{
namespace hidden_nic
{

// Realtek Semiconductor RTL8111/8168/8411 PCI Express Gigabit Ethernet Controller
inline uint32_t vendor_device = 0x816810EC;

// Intel PCI Bridge at 0::1c::0
// inline uint32_t vendor_device = 0xA2948086;

uint64_t g_bus = 0;
uint64_t g_device = 0;
uint64_t g_function = 0;

using namespace eapis::intel_x64;

bool
handle_cfc_in(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);

    // uint32_t address = 0x80000000 | g_bus << 16 | g_device << 11 | g_function << 8;
    // auto cf8 = ::x64::portio::ind(0xCF8);

    info.val = ::x64::portio::ind(0xCFC);
    if (info.val == vendor_device) {
        info.val = 0xffffffffffffffff;
        return true;
    }

    return false;
}

bool
handle_cfc_out(gsl::not_null<vcpu_t *> vcpu, io_instruction_handler::info_t &info)
{
    bfignored(vcpu);
    bfignored(info);
    // ::x64::portio::outd(0xCFC, gsl::narrow_cast<uint32_t>(info.val));
    return false;
}

void
enable( gsl::not_null<eapis::intel_x64::vcpu *> vcpu, uint32_t bus,
    uint32_t device, uint32_t function)
{

    g_bus = bus;
    g_device = device;
    g_function = function;

    vcpu->add_io_instruction_handler(
        0xCFC,
        io_instruction_handler::handler_delegate_t::create <handle_cfc_in>(),
        io_instruction_handler::handler_delegate_t::create <handle_cfc_out>()
    );

    // bfdebug_info(0, "Hidden NIC initialized");
}

}
}
