//
// Bareflank Hypervisor
// Copyright (C) 2015 Assured Information Security, Inc.
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

// TIDY_EXCLUSION=-cppcoreguidelines-pro-type-vararg
//
// Reason:
//    The Linux APIs require the use of var-args, so this test has to be
//    disabled.
//

#include <iostream>
#include <ioctl_private.h>

#include <bfgsl.h>
#include <bfdriverinterface.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>

// -----------------------------------------------------------------------------
// Unit Test Seems
// -----------------------------------------------------------------------------

int
bfm_ioctl_open()
{
    return open("/dev/bareflank_builder", O_RDWR);
}

int64_t
bfm_write_ioctl(int fd, unsigned long request, const void *data)
{
    return ioctl(fd, request, data);
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

ioctl_private::ioctl_private()
{
    if ((fd = bfm_ioctl_open()) < 0) {
        throw std::runtime_error("failed to open to the builder driver");
    }
}

ioctl_private::~ioctl_private()
{ close(fd); }

void
ioctl_private::call_ioctl_create_from_elf(create_from_elf_args &args)
{
    if (bfm_write_ioctl(fd, IOCTL_CREATE_FROM_ELF_CMD, &args) < 0) {
        throw std::runtime_error("ioctl failed: IOCTL_CREATE_FROM_ELF_CMD");
    }
}

void
ioctl_private::call_ioctl_destroy(domainid_t domainid) noexcept
{
    if (bfm_write_ioctl(fd, IOCTL_DESTROY_CMD, &domainid) < 0) {
        std::cerr << "[ERROR] ioctl failed: IOCTL_DESTROY_CMD\n";
    }
}
