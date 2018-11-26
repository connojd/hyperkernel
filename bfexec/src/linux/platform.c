/**
 * Bareflank Hyperkernel
 * Copyright (C) 2018 Assured Information Security, Inc.
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

#define _GNU_SOURCE

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#define MMAP_FLAGS (MAP_POPULATE | MAP_LOCKED | MAP_PRIVATE | MAP_ANONYMOUS)

/* -------------------------------------------------------------------------- */
/* Internal helpers                                                           */
/* -------------------------------------------------------------------------- */

static void *mmap_alloc(uint64_t size, int prot, int flags)
{
    void *addr = mmap(NULL, size, prot, flags, -1, 0);

    if (addr == MAP_FAILED) {
        printf("mmap failed: %s\n", strerror(errno));
        return NULL;
    }

    return addr;
}

static void mmap_free(void *addr, uint64_t len)
{
    if (!addr) {
        return;
    }

    if (munmap(addr, len) < 0) {
        printf("munmap failed: %s\n", strerror(errno));
    }
}

/* -------------------------------------------------------------------------- */
/* API implementation                                                         */
/* -------------------------------------------------------------------------- */

int64_t platform_init(void)
{
    struct rlimit as, ml;

    if (getrlimit(RLIMIT_AS, &as) < 0) {
        printf("getrlimit (AS) failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    ml.rlim_cur = as.rlim_cur;
    ml.rlim_max = as.rlim_max;

    if (setrlimit(RLIMIT_MEMLOCK, &ml) < 0) {
        printf("setrlimit (MEMLOCK) failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /**
     * Sanity check
     *
     * We do this to make sure the limits were actually changed. The process
     * needs to have super-user privileges for this to work.
     */

    if (getrlimit(RLIMIT_MEMLOCK, &ml) < 0) {
        printf("getrlimit (MEMLOCK) failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    if (ml.rlim_cur != as.rlim_cur || ml.rlim_max != as.rlim_max) {
        printf("MEMLOCK sanity check failed (be sure to run as root):\n");
        printf("    memlock cur: %x max: %x\n", ml.rlim_cur, ml.rlim_max);
        printf("    as      cur: %x max: %x\n", as.rlim_cur, as.rlim_max);
        return EXIT_FAILURE;
    }

    /**
     * For simplicity, we ask the kernel to lock all future pages in memory.
     * Every byte of memory allocated from this point forward will be locked
     * into RAM. Obviously this could be a problem if we use alot of pages, in
     * which case we will have to revisit this with a more elegant solution.
     */

    if (mlockall(MCL_FUTURE) < 0) {
        printf("mlockall failed: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    return 0;
}

void *
platform_alloc_rw(uint64_t len)
{ return mmap_alloc(len, PROT_READ | PROT_WRITE, MMAP_FLAGS); }

void *
platform_alloc_rwe(uint64_t len)
{ return mmap_alloc(len, PROT_READ | PROT_WRITE | PROT_EXEC, MMAP_FLAGS); }

void
platform_free_rw(void *addr, uint64_t len)
{ mmap_free(addr, len); }

void
platform_free_rwe(void *addr, uint64_t len)
{ mmap_free(addr, len); }

void *
platform_memset(void *ptr, char value, uint64_t num)
{ return memset(ptr, value, num); }

void *
platform_memcpy(void *dst, const void *src, uint64_t num)
{ return memcpy(dst, src, num); }

void platform_sleep(long usec)
{
    struct timespec ts;

    ts.tv_sec = 0;
    ts.tv_nsec = usec;

    int err = nanosleep(&ts, NULL);
    if (err) {
        printf("nanosleep failed: %s\n", strerror(errno));
    }
}
