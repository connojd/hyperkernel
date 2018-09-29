//
// Bareflank Hyperkernel
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

#include <stdint.h>

uintptr_t _vmcall(
    uintptr_t r1, uintptr_t r2, uintptr_t r3, uintptr_t r4);

const char *msg = "Hello from VM\n";

void _start(void)
{
    _vmcall(0xBF86000000000100, 0x6E, (uintptr_t)msg, 14);
    _vmcall(0xBF86000000000100, 0xF4, 0, 0);
}
