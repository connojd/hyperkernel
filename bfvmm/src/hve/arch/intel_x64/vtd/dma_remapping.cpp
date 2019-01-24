#include <bfvmm/hve/arch/intel_x64/exit_handler.h>
#include <bfvmm/memory_manager/memory_manager.h>
#include <bfvmm/memory_manager/arch/x64/cr3/mmap.h>
#include <eapis/hve/arch/intel_x64/vcpu.h>
#include <bfcallonce.h>

#include "hve/arch/intel_x64/vtd/vtd_sandbox.h"

namespace vtd_sandbox
{
namespace dma_remapping
{

intel_x64::vtd::mmap g_vtd_mmap{};
bfn::once_flag vtd_mmap_init_flag{};
bfn::once_flag remapping_enabled_flag{};
bfn::once_flag fini_flag{};

using namespace eapis::intel_x64;


void
enable_dma_remapping(intel_x64::vtd::mmap &vtd_mmap)
{
    // bfdebug_info(0, "Initializing DMA Remapping");

    // -------------------------------------------------------------------------
    // Map with hard-coded virtual address and CR3 API
    // -------------------------------------------------------------------------
    auto iommu_base_virt = reinterpret_cast<uintptr_t>(0x100000UL);
    g_cr3->map_4k(
        iommu_base_virt,
        vtd_sandbox::iommu_base_phys,
        bfvmm::x64::cr3::mmap::attr_type::read_write,
        bfvmm::x64::cr3::mmap::memory_type::uncacheable
    );
    bfdebug_subnhex(0, "IOMMU virtual", iommu_base_virt);
    bfdebug_subnhex(0, "IOMMU physical", vtd_sandbox::iommu_base_phys);
    intel_x64::vtd::iommu::base_addr = iommu_base_virt;

    // -------------------------------------------------------------------------
    // Check current DMA remapping status
    // -------------------------------------------------------------------------
    if (intel_x64::vtd::iommu::gsts_reg::tes::is_enabled()) {
        bfalert_info(0, "WARNING: DMA Translation is already enabled");
    }

    if (intel_x64::vtd::iommu::gsts_reg::fls::is_enabled()) {
        bfalert_info(0, "WARNING: Fault logging is already enabled");
    }

    if (intel_x64::vtd::iommu::gsts_reg::qies::is_enabled()) {
        bfalert_info(0, "WARNING: Queued invalidation is already enabled");
    }

    // -------------------------------------------------------------------------
    // Set the DMA root table pointer
    // -------------------------------------------------------------------------
    bfdebug_info(0, "Setting up Root table pointer for DMA remapping...");
    auto root_table_value = vtd_mmap.phys_addr();
    intel_x64::vtd::iommu::rtaddr_reg::rtt::disable(root_table_value);
    intel_x64::vtd::iommu::rtaddr_reg::set(root_table_value);
    intel_x64::vtd::iommu::gcmd_reg::srtp::enable();
    while(1) {
        auto keep_waiting = intel_x64::vtd::iommu::gsts_reg::rtps::is_disabled();
        if (!keep_waiting) break;
        bfdebug_info(0, "... waiting on root table pointer status bit ...");
    }
    bfdebug_info(0, "done");

    // -------------------------------------------------------------------------
    // Initialize fault recording register(s)
    // -------------------------------------------------------------------------
    bfdebug_info(0, "Initializing IOMMU fault recording registers");
    auto fault_reg_count = intel_x64::vtd::iommu::cap_reg::nfr::get();
    bfdebug_subnhex(0, "Fault recording register count:", fault_reg_count + 1);

    auto fault_reg_offset = intel_x64::vtd::iommu::cap_reg::fro::get() * 16;
    bfdebug_subnhex(0, "Fault recording register offset:", fault_reg_offset);

    auto frr_val = intel_x64::vtd::iommu::frr::get();

    if(intel_x64::vtd::iommu::frr::f::is_enabled(frr_val)) {
        bfdebug_info(0, "Resetting fault recording register 0...");
        using frr_value_type = struct frr_value_type { uint64_t data[2]{0}; };
        auto fault_reg_0 = reinterpret_cast<frr_value_type *>(intel_x64::vtd::iommu::base_addr + fault_reg_offset);
        fault_reg_0->data[1] = 0x8000000000000000;
        bfdebug_info(0, "done");
    }

    bfdebug_info(0, "Clearing fault status register...");
    intel_x64::vtd::iommu::fsts_reg::pfo::enable();
    bfdebug_info(0, "done");

    // -------------------------------------------------------------------------
    // Enable DMA remapping
    // -------------------------------------------------------------------------
    bfdebug_info(0, "Enabling DMA remapping...");
    auto gsts_reg_val = ::intel_x64::vtd::iommu::gsts_reg::get();
    gsts_reg_val = gsts_reg_val & 0x96FFFFFF;
    intel_x64::vtd::iommu::gcmd_reg::te::enable(gsts_reg_val);
    intel_x64::vtd::iommu::gcmd_reg::set(gsts_reg_val);
    while(1) {
        auto keep_waiting = intel_x64::vtd::iommu::gsts_reg::tes::is_disabled();
        if (!keep_waiting) break;
        bfdebug_info(0, "... waiting on translation enable status bit ...");
    }
    bfdebug_info(0, "done");

    // -------------------------------------------------------------------------
    // Check fault recording to see if we messed anything up
    // -------------------------------------------------------------------------
    for (auto i = 0; i < 1000000; i++) {
        if(intel_x64::vtd::iommu::fsts_reg::ppf::is_enabled()) {
            printf("\n");
            bferror_info(0, "Fault occurred during IOMMU initialization:");
            intel_x64::vtd::iommu::frr::dump(0);
            printf("\n");
            break;
        }
    }
    frr_ready = true;

    // -------------------------------------------------------------------------
    // Dump post-initialized state
    // -------------------------------------------------------------------------
    // bfdebug_info(0, "-------------------------------------------");
    // bfdebug_info(0, "        IOMMU (Post-Initialization) ");
    // bfdebug_info(0, "-------------------------------------------");
    // intel_x64::vtd::iommu::dump(0);
    // printf("\n");
}

void
disable_dma_remapping()
{
    // -------------------------------------------------------------------------
    // Disable DMA remapping
    // -------------------------------------------------------------------------
    if (intel_x64::vtd::iommu::gsts_reg::tes::is_enabled()) {
        // bfdebug_info(0, "Disabling DMA Remapping");
        intel_x64::vtd::iommu::gcmd_reg::te::disable();
        while(1) {
            auto keep_waiting = intel_x64::vtd::iommu::gsts_reg::tes::is_enabled();
            if (!keep_waiting) break;
            // bfdebug_info(0, "... waiting on translation enable status bit ...");
        }
        // bfdebug_info(0, "done");
    }

    // -------------------------------------------------------------------------
    // Clear root-table pointer
    // -------------------------------------------------------------------------
    if(intel_x64::vtd::iommu::gsts_reg::rtps::is_enabled()) {
        // bfdebug_info(0, "Clearing DMA root table pointer");
        intel_x64::vtd::iommu::rtaddr_reg::set(0);
        intel_x64::vtd::iommu::gcmd_reg::srtp::enable();
        while(1) {
            auto keep_waiting = intel_x64::vtd::iommu::gsts_reg::rtps::is_disabled();
            if (!keep_waiting) break;
            // bfdebug_info(0, "... waiting on root table pointer status bit ...");
        }
        // bfdebug_info(0, "done");
    }
}

// void
// handle_fini(bfobject *data)
// {
//     bfignored(data);
//     bfn::call_once(fini_flag, [&] {
//         disable_dma_remapping();
//     });
// }

void
map_bus(uint64_t bus, uint64_t dma_domain_id, eapis::intel_x64::ept::mmap &mmap)
{
    bfn::call_once(vtd_mmap_init_flag, [&] {
        g_vtd_mmap.init();
    });

    g_vtd_mmap.map_bus(bus, dma_domain_id, mmap);
}

void
enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu)
{
    bfignored(vcpu);

    bfn::call_once(vtd_mmap_init_flag, [&] {
        enable_dma_remapping(g_vtd_mmap);
    });

    // vcpu->add_fini_delegate(
    //     bfvmm::vcpu::fini_delegate_t::create<handle_fini>()
    // );
}

}
}
