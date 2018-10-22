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

#ifndef HYPERKERNEL_BFDRIVERINTERFACE_H
#define HYPERKERNEL_BFDRIVERINTERFACE_H

#include <bfdriverinterface.h>

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Common                                                                     */
/* -------------------------------------------------------------------------- */

#ifndef HKD_NAME
#define HKD_NAME "hkd"
#endif

#ifndef HKD_MAGIC
#define HKD_MAGIC 0xBF
#endif

#ifndef HKD_DEVICETYPE
#define HKD_DEVICETYPE 0xCAFE
#endif

#define HKD_ADD_EVENT_HANDLER_CMD 0x1

/* -------------------------------------------------------------------------- */
/* Linux Interfaces                                                           */
/* -------------------------------------------------------------------------- */

#ifdef __linux__

/**
 * struct hkd_event_handler
 *
 * @pid[in] the pid of the calling process
 * @eventfd[in] the eventfd of the calling process
 * @vector[out] the IDT vector associated with the event
 * @irq the Linux irq associated with the event
 */
struct hkd_event_handler {
    unsigned int pid;
    unsigned int eventfd;
    unsigned int vector;
    unsigned int irq;
};

#define HKD_ADD_EVENT_HANDLER \
        _IOWR(HKD_MAGIC, HKD_ADD_EVENT_HANDLER_CMD, struct hkd_event_handler)

#endif

/* -------------------------------------------------------------------------- */
/* Windows Interfaces                                                         */
/* -------------------------------------------------------------------------- */

#if defined(_WIN32) || defined(__CYGWIN__)

#include <initguid.h>

DEFINE_GUID(
    GUID_DEVINTERFACE_bareflank,
    0x1d9c9218,
    0x3c88,
    0x4b81,
    0x8e,
    0x81,
    0xb4,
    0x62,
    0x2a,
    0x4d,
    0xcb,
    0x44);

#define HKD_ADD_MODULE CTL_CODE(HKD_DEVICETYPE, HKD_ADD_MODULE_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)
#define HKD_LOAD_VMM CTL_CODE(HKD_DEVICETYPE, HKD_LOAD_VMM_CMD, METHOD_BUFFERED, 0)
#define HKD_UNLOAD_VMM CTL_CODE(HKD_DEVICETYPE, HKD_UNLOAD_VMM_CMD, METHOD_BUFFERED, 0)
#define HKD_START_VMM CTL_CODE(HKD_DEVICETYPE, HKD_START_VMM_CMD, METHOD_BUFFERED, 0)
#define HKD_STOP_VMM CTL_CODE(HKD_DEVICETYPE, HKD_STOP_VMM_CMD, METHOD_BUFFERED, 0)
#define HKD_DUMP_VMM CTL_CODE(HKD_DEVICETYPE, HKD_DUMP_VMM_CMD, METHOD_OUT_DIRECT, FILE_READ_DATA)
#define HKD_VMM_STATUS CTL_CODE(HKD_DEVICETYPE, HKD_VMM_STATUS_CMD, METHOD_BUFFERED, FILE_READ_DATA)
#define HKD_SET_VCPUID CTL_CODE(HKD_DEVICETYPE, HKD_SET_VCPUID_CMD, METHOD_IN_DIRECT, FILE_WRITE_DATA)

#endif

#ifdef __cplusplus
}
#endif

#endif
