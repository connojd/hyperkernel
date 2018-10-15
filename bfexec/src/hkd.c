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

#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <hkd/entry.h>

int hkd_open()
{
    return open("/dev/hkd", O_RDWR);
}

int hkd_write(int fd, unsigned long request, const void *data)
{
    return ioctl(fd, request, data);
}

int hkd_close(int fd)
{
    return close(fd);
}

int hkd_set_signal(int fd, int signum)
{
    return hkd_write(fd, HKD_SET_SIGNAL, &signum);
}

int hkd_set_signal_pid(int fd, uint64_t pid)
{
    return hkd_write(fd, HKD_SET_SIGNAL_PID, &pid);
}

int hkd_request_irq(int fd, uint64_t irq)
{
    return hkd_write(fd, HKD_REQUEST_IRQ, &irq);
}
