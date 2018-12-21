#ifndef VTD_SANDBOX_H
#define VTD_SANDBOX_H

#include "mmap.h"
#include "imap.h"

namespace vtd_sandbox
{

// The two NIC interrupt vectors to be remapped to/from each other
inline uint64_t g_visr_vector = 0;
inline uint64_t g_ndvm_vector = 0;

// The id of the NDVM's vCPU (needed as a destination for interrupt injection)
inline uint64_t ndvm_vcpu_id = 0;


inline uintptr_t iommu_base_phys = 0xfed91000;     // Gigabyte and Surface Pro
// inline uintptr_t iommu_base_phys = 0xfec10000;     // VMware Fusion

namespace hidden_nic
{
    void enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu, uint32_t bus,
        uint32_t device, uint32_t function);
}

namespace visr_device
{
    void enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu, uint32_t bus,
        uint32_t device, uint32_t function);
}

namespace hidden_bridge
{
    void enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu, uint32_t bus,
        uint32_t device, uint32_t function);
}

namespace dma_remapping
{
    void enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu);
    void map_bus(uint64_t bus, uint64_t dma_domain_id, eapis::intel_x64::ept::mmap &mmap);
}

namespace interrupt_remapping
{
    void enable(gsl::not_null<eapis::intel_x64::vcpu *> vcpu, uint64_t bus,
        uint64_t device, uint64_t function);
}

}

#endif
