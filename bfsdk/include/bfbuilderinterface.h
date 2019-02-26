/*
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

#ifndef BUILDERINTERFACE_H
#define BUILDERINTERFACE_H

#include <bftypes.h>
#include "bfhypercall.h"

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

#ifndef BUILDER_NAME
#define BUILDER_NAME "bareflank_builder"
#endif

#ifndef BUILDER_MAJOR
#define BUILDER_MAJOR 151
#endif

#ifndef BUILDER_DEVICETYPE
#define BUILDER_DEVICETYPE 0xF00D
#endif

#define IOCTL_CREATE_FROM_ELF_CMD 0x901
#define IOCTL_DESTROY_CMD 0x902

/**
 * @struct create_from_elf_args
 *
 * This structure is used to load and ELF file as a guest VM. This is the
 * information the builder needs to create a domain and load its resources
 * prior to execution.
 *
 * @var create_from_elf_args::file
 *     the ELF file to load
 * @var create_from_elf_args::file_size
 *     the length of the ELF file to load
 * @var create_from_elf_args::cmdl
 *     the command line arguments to pass to the Linux kernel on boot
 * @var create_from_elf_args::cmdl_length
 *     the length of the command line arguments
 * @var create_from_elf_args::uart
 *     defaults to 0. If non zero, the hypervisor will be told to pass-through
 *     the provided uart.
 * @var create_from_elf_args::ram_size
 *     the amount of RAM to give to the domain
 * @var create_from_elf_args::domainid
 *     (out) the domain ID of the VM that was created
 */
struct create_from_elf_args {
    const char *file;
    uint64_t file_size;

    const char *cmdl;
    uint64_t cmdl_size;

    uint64_t uart;
    uint64_t pt_uart;

    uint64_t size;
    uint64_t is_ndvm;
    uint64_t domainid;
};

/* -------------------------------------------------------------------------- */
/* Linux Interfaces                                                           */
/* -------------------------------------------------------------------------- */

#ifdef __linux__

#define IOCTL_CREATE_FROM_ELF _IOWR(BUILDER_MAJOR, IOCTL_CREATE_FROM_ELF_CMD, struct create_from_elf_args *)
#define IOCTL_DESTROY _IOW(BUILDER_MAJOR, IOCTL_DESTROY_CMD, domainid_t *)

#endif

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)

#include <initguid.h>

DEFINE_GUID(GUID_DEVINTERFACE_builder,
    0x0156f59a, 0xdf90, 0x4ac6, 0x85, 0x3d, 0xcf, 0xd9, 0x3e, 0x25, 0x65, 0xc2);

#define IOCTL_CREATE_FROM_ELF CTL_CODE(BUILDER_DEVICETYPE, IOCTL_CREATE_FROM_ELF_CMD, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_DESTROY CTL_CODE(BUILDER_DEVICETYPE, IOCTL_DESTROY_CMD, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
