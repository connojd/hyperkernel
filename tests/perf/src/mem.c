/*
 * Bareflank Hyperkernel
 *
 * Copyright (C) 2015 Assured Information Security, Inc.
 * Author: Rian Quinn        <quinnr@ainfosec.com>
 * Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

// Global perf control MSRs
// see section 2.1, volume 4
#define PERF_GLOBAL_CTRL_ADDR 0x38f
#define PERF_GLOBAL_INUSE_ADDR 0x392

// CPUID leafs and subleafs
// see CPUID instruction in volume 2
#define PERF_LEAF 0x0a
#define VERSION_LEAF 0x01
#define NULL_SUBLEAF 0x0

// Event select macros
// see section 18.2.1.1, volume 3
#define EVT_USR (1ULL << 16) // monitor ring 3
#define EVT_OS (1ULL << 17)  // monitor ring 0
#define EVT_EN (1ULL << 22)  // enable the pmc
#define EVT_MASK (EVT_USR | EVT_OS | EVT_EN)

// Event select MSRs
#define EVTSEL0_ADDR 0x186 // exists when cpuid.0a:eax[15:8] > 0
#define EVTSEL1_ADDR 0x187 // exists when cpuid.0a:eax[15:8] > 1
#define EVTSEL2_ADDR 0x188 // exists when cpuid.0a:eax[25:8] > 2
#define EVTSEL3_ADDR 0x189 // exists when cpuid.0a:eax[25:8] > 3
#define EVTSEL4_ADDR 0x18A // exists when cpuid.0a:eax[15:8] = 8
#define EVTSEL5_ADDR 0x18B // exists when cpuid.0a:eax[15:8] = 8
#define EVTSEL6_ADDR 0x18C // exists when cpuid.0a:eax[25:8] = 8
#define EVTSEL7_ADDR 0x18D // exists when cpuid.0a:eax[25:8] = 8

// PMC MSRs
#define PMC0_ADDR 0xc1 // exists when cpuid.0a:eax[15:8] > 0
#define PMC1_ADDR 0xc2 // exists when cpuid.0a:eax[15:8] > 1
#define PMC2_ADDR 0xc3 // exists when cpuid.0a:eax[15:8] > 2
#define PMC3_ADDR 0xc4 // exists when cpuid.0a:eax[15:8] > 3
#define PMC4_ADDR 0xc5 // exists when cpuid.0a:eax[15:8] > 4
#define PMC5_ADDR 0xc6 // exists when cpuid.0a:eax[15:8] > 5
#define PMC6_ADDR 0xc7 // exists when cpuid.0a:eax[15:8] > 6
#define PMC7_ADDR 0xc8 // exists when cpuid.0a:eax[15:8] > 7

// See Table 4-16 for the RDPMC instruction
// PMC indexes for 06_5e processors:
#define PMC0_INDEX 0UL
#define PMC1_INDEX 1UL
#define PMC2_INDEX 2UL
#define PMC3_INDEX 3UL

// 4-7 are valid only if hyperthreading is disabled
#define PMC4_INDEX 4UL
#define PMC5_INDEX 5UL
#define PMC6_INDEX 6UL
#define PMC7_INDEX 7UL

/* Programming EVTSELx MSRs
 *
 * value = (bits[7:0] event select) | (bits[15:8] umask) | EVT_MASK
 */

/*
 * Valid perf events for processors with
 * display family = 0x06 and display model = 0x5e or 0x4e
 * (can use cpu_display_{family,model} below to determine this)
 *
 * See section 19.3, volume 3
 * Table 19-1: architectural perf events
 * Table 19-2: architecture events supported by fixed counters
 * Table 19-4: non-architectural events (listed below)
 *
 * format: EVT_MASK | 0x<umask byte><event select byte>
 */
// Counts 1 per cycle for each PMH that is busy w/ page walk for a load
#define LOAD_WALK_CYCLES (EVT_MASK | 0x1008ULL)

// Counts 1 per cycle for each PMH that is busy w/ page walk for a store
#define STORE_WALK_CYCLES (EVT_MASK | 0x1049ULL)

// Count when load misses in all TLB levels that cause page walks.
#define LOAD_CAUSES_WALK (EVT_MASK | 0x0108ULL)

// Count when store misses in all TLB levels that cause page walks.
#define STORE_CAUSES_WALK (EVT_MASK | 0x0149ULL)

// Counts when loads that miss DTLB but hit STLB
#define LOAD_MISS_STLB_HIT (EVT_MASK | 0x2008ULL)

// Counts when stores that miss DTLB but hit STLB
#define STORE_MISS_STLB_HIT (EVT_MASK | 0x2049ULL)

// Counts 1 per cycle for each PMH that is busy w/ page walk for fetch
#define FETCH_WALK_CYCLES (EVT_MASK | 0x1085ULL)

// Counts 1 per cycle for each PMH that is busy w/ EPT walk
#define EPT_WALK_CYCLES (EVT_MASK | 0x104fULL)


struct cpuid_regs {
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
};

/*
 * Retrieves cpuid with leaf = @param leaf, subleaf = 0 and writes
 * e{a,b,c,d}x to regs
 *
 * Note: this cpuid does not clear the registers before calling cpuid
 * and thus is not fit for use in settings that require precise timing
 * measurements.
 */
void
cpuid(uint32_t leaf, struct cpuid_regs *regs)
{
    __asm volatile(
        "cpuid" :
        "=a"(regs->eax), "=b"(regs->ebx), "=c"(regs->ecx), "=d"(regs->edx) :
        "a"(leaf), "c"(0)
    );
}

uint32_t perf_version_id()
{
    struct cpuid_regs regs;
    cpuid(PERF_LEAF, &regs);
    return (regs.eax & 0xffU) >> 0;
}

uint32_t perf_nr_pmcs()
{
    struct cpuid_regs regs;
    cpuid(PERF_LEAF, &regs);
    return (regs.eax & 0xff00U) >> 8;
}

uint32_t perf_pmc_bit_width()
{
    struct cpuid_regs regs;
    cpuid(PERF_LEAF, &regs);
    return (regs.eax & 0xff0000U) >> 16;
}

uint32_t perf_nr_fixed_pmcs()
{
    uint32_t id = perf_version_id();
    if (id <= 1) {
        printf("WARNING: requested nr_fixed_pmcs, but version_id = %u", id);
        return 0;
    }

    struct cpuid_regs regs;
    cpuid(PERF_LEAF, &regs);
    return (regs.edx & 0x1fU) >> 0;
}

uint32_t perf_fixed_pmc_bit_width()
{
    uint32_t id = perf_version_id();
    if (id <= 1) {
        printf("WARNING: requested fixed_pmc_bit_width, but version_id = %u", id);
        return 0;
    }

    struct cpuid_regs regs;
    cpuid(PERF_LEAF, &regs);
    return (regs.edx & 0x1fe0U) >> 5;
}

uint32_t cpu_version()
{
    struct cpuid_regs regs;
    cpuid(VERSION_LEAF, &regs);
    return regs.eax;
}

uint32_t cpu_version_model(uint32_t version)
{
    return (version & 0xf0) >> 4;
}

uint32_t cpu_version_family(uint32_t version)
{
    return (version & 0xf00) >> 8;
}

uint32_t cpu_version_ext_family(uint32_t version)
{
    return (version & 0xff00000) >> 20;
}

uint32_t
cpu_version_ext_model(uint32_t version)
{
    return (version & 0xf0000) >> 16;
}

uint32_t cpu_display_family()
{
    uint32_t version = cpu_version();
    uint32_t family = cpu_version_family(version);

    if (family != 0x0f) {
        return family;
    } else {
        return cpu_version_ext_family(version) + family;
    }
}

uint32_t cpu_display_model()
{
    uint32_t version = cpu_version();
    uint32_t family = cpu_version_family(version);
    uint32_t model = cpu_version_model(version);
    uint32_t ext_model = cpu_version_ext_model(version);

    if (family == 0x0f || family == 0x06) {
        return (ext_model << 4) + model;
    } else {
        return model;
    }
}

void wrmsr(uint32_t addr, uint64_t data)
{
    uint32_t edx = (uint32_t)(data >> 32);
    uint32_t eax = (uint32_t)(data);

    __asm volatile("wrmsr" : : "c"(addr), "d"(edx), "a"(eax));
}

uint64_t rdmsr(uint32_t addr)
{
    uint32_t edx, eax;

    __asm volatile("rdmsr" : "=d"(edx), "=a"(eax) : "c"(addr));
    return ((uint64_t)edx << 32) | eax;
}

void invlpg_range(char *addr, long int npages, long int pagesz)
{
    for (int i = 0; i < npages; i++) {
        __asm volatile("invlpg (%0)" : : "r"(addr + i * pagesz) : "memory");
    }
}

void start_pmcs()
{
    // enable pmcs in global ctrl
    wrmsr(PERF_GLOBAL_CTRL_ADDR, 0xff);

    wrmsr(EVTSEL0_ADDR, EPT_WALK_CYCLES);
    wrmsr(EVTSEL1_ADDR, FETCH_WALK_CYCLES);
    wrmsr(EVTSEL2_ADDR, LOAD_WALK_CYCLES);
    wrmsr(EVTSEL3_ADDR, STORE_WALK_CYCLES);
    wrmsr(EVTSEL4_ADDR, LOAD_CAUSES_WALK);
    wrmsr(EVTSEL5_ADDR, STORE_CAUSES_WALK);
    wrmsr(EVTSEL6_ADDR, LOAD_MISS_STLB_HIT);
    wrmsr(EVTSEL7_ADDR, STORE_MISS_STLB_HIT);
}

uint64_t rdpmc(uint32_t index)
{
    uint32_t edx;
    uint32_t eax;

    __asm volatile("rdpmc" : "=d" (edx), "=a" (eax) : "c" (index));

    uint64_t count = ((uint64_t)edx << 32U) | eax;
    uint64_t mask = ~(0xffffffffffffffffULL << perf_pmc_bit_width());
    return count & mask;
}

void invept()
{
    uint64_t dummy_desc[2] = {0};
    uint64_t dummy_type = 1;

    __asm volatile("invept %1, %0" :: "a"(dummy_type), "g"(dummy_desc[0]) : "memory");
}

void clear_pmcs()
{
    wrmsr(PMC0_ADDR, 0);
    wrmsr(PMC1_ADDR, 0);
    wrmsr(PMC2_ADDR, 0);
    wrmsr(PMC3_ADDR, 0);
    wrmsr(PMC4_ADDR, 0);
    wrmsr(PMC5_ADDR, 0);
    wrmsr(PMC6_ADDR, 0);
    wrmsr(PMC7_ADDR, 0);
}

void print_inuse_perf_msrs()
{
    uint64_t msr = rdmsr(PERF_GLOBAL_INUSE_ADDR);
    printf("perf inuse msrs:");
    printf(" evtsel: 0x%lu", msr & 0xff);
    printf(", fixed: 0x%lu", (msr >> 32) & 0x7);
    printf(", pmi: 0x%lu\n", (msr >> 63) & 0x1);
}

/*
 * argv[0] = npages
 * argv[1] = pagesz
 * addr = 0x40000000UL
 */
int
main(int argc, const char *argv[])
{
    if (argc != 3) {
        printf("ERROR: need args filename, npages, pagesz\n");
        return 22;
    }

    long int npages = strtol(argv[1], NULL, 0);
    long int pagesz = strtol(argv[2], NULL, 0);

    char *addr = (char *)0x40000000UL;
    int64_t dummy_type = 1;
    int64_t dummy_desc[2] = {0};

    start_pmcs();

    __asm volatile(
        // flush linear mappings
        "mov %%cr4, %%rax\t\n"
        "xor $0x80, %%rax\t\n"
        "mov %%rax, %%cr4\t\n"
        "xor $0x80, %%rax\t\n"
        "mov %%rax, %%cr4\t\n"

        // flush gpa mappings
        "invept %1, %0\t\n"

        :
        : "a"(dummy_type), "g"(dummy_desc[0])
        : "memory","cc"
    );

    clear_pmcs();

    uint64_t pmc0 = rdmsr(PMC0_ADDR);
    uint64_t pmc1 = rdmsr(PMC1_ADDR);
    uint64_t pmc2 = rdmsr(PMC2_ADDR);
    uint64_t pmc3 = rdmsr(PMC3_ADDR);
    uint64_t pmc4 = rdmsr(PMC4_ADDR);
    uint64_t pmc5 = rdmsr(PMC5_ADDR);
    uint64_t pmc6 = rdmsr(PMC6_ADDR);
    uint64_t pmc7 = rdmsr(PMC7_ADDR);

    uint64_t nr_accesses = (pagesz == 0x1000) ? npages / 512 : npages;

    // nontemporal accesses (with cache flush above)
    for (int i = 0; i < nr_accesses; i++) {
        *(addr + i * pagesz) = 't';
    }

    // temporal accesses (without a cache flush above)
//    for (int i = 0; i < nr_accesses; i++) {
//        *(addr + i) = 't';
//    }

    struct cpuid_regs regs;
    cpuid(0, &regs);

    printf("%lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
        npages,
        pagesz,
        rdmsr(PMC0_ADDR) - pmc0,
        rdmsr(PMC1_ADDR) - pmc1,
        rdmsr(PMC2_ADDR) - pmc2,
        rdmsr(PMC3_ADDR) - pmc3,
        rdmsr(PMC4_ADDR) - pmc4,
        rdmsr(PMC5_ADDR) - pmc5,
        rdmsr(PMC6_ADDR) - pmc6,
        rdmsr(PMC7_ADDR) - pmc7
    );

//    printf("perf_version_id: %lu\n", perf_version_id());
//    printf("perf_nr_pmcs: %lu\n", perf_nr_pmcs());
//    printf("perf_pmc_bit_width: %lu\n", perf_pmc_bit_width());
//    printf("cpu_display_family: 0x%lx\n", cpu_display_family());
//    printf("cpu_display_model: 0x%lx\n", cpu_display_model());

    return 0;
}
