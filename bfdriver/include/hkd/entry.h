/*
 * Bareflank PV Interface
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

/* -------------------------------------------------------------------------- */
/* Hyperkernel Driver (hkd) IOCTL Interface                                   */
/* -------------------------------------------------------------------------- */

#define HKD_SET_SIGNAL_CMD 1
#define HKD_SET_SIGNAL_PID_CMD 2
#define HKD_REQUEST_IRQ_CMD 3

#ifdef __linux__

#define HKD_MAJOR 151
#define HKD_NAME "hkd"

#define HKD_SET_SIGNAL \
       _IOW(HKD_MAJOR, HKD_SET_SIGNAL_CMD, int *)

#define HKD_SET_SIGNAL_PID \
       _IOW(HKD_MAJOR, HKD_SET_SIGNAL_PID_CMD, uint64_t *)

#define HKD_REQUEST_IRQ \
       _IOR(HKD_MAJOR, HKD_REQUEST_IRQ_CMD, uint64_t *)

#endif
