//
// Bareflank Extended APIs
// Copyright (C) 2018 Assured Information Security, Inc.
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

#ifndef BFEXEC_HKD_H
#define BFEXEC_HKD_H

#include <bftypes.h>
#include <bfmemory.h>
#include <bferrorcodes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
#define NOEXCEPT noexcept
#else
#define NOEXCEPT
#endif

#ifdef __cplusplus
extern "C" {
#endif

int hkd_open() NOEXCEPT;
int hkd_close(int fd) NOEXCEPT;
int hkd_write(int fd, unsigned long request, const void *data) NOEXCEPT;
int hkd_read(int fd, unsigned long request, void *data) NOEXCEPT;

int hkd_set_signal(int fd, int signum) NOEXCEPT;
int hkd_set_signal_pid(int fd, pid_t pid) NOEXCEPT;
int hkd_request_irq(int fd, uint64_t irq) NOEXCEPT;

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
