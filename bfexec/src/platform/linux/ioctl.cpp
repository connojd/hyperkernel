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

#include <ioctl.h>
#include <ioctl_private.h>

ioctl::ioctl() :
    m_d {std::make_unique<ioctl_private>()}
{ }

void
ioctl::call_ioctl_create_from_elf(create_from_elf_args &args)
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get())) {
        d->call_ioctl_create_from_elf(args);
    }
}

void
ioctl::call_ioctl_destroy(domainid_t domainid) noexcept
{
    if (auto d = dynamic_cast<ioctl_private *>(m_d.get())) {
        d->call_ioctl_destroy(domainid);
    }
}
