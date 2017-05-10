#include "timing.h"

uint64_t rdtsc() {
    uint64_t a, d;
    __asm volatile ("mfence");
    __asm volatile ("rdtsc" : "=a" (a), "=d" (d));
    __asm volatile ("mfence");
    return (d << 32) | a;
}
