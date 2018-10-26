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

#ifndef HKD_H
#define HKD_H

#include <linux/eventfd.h>
#include <linux/miscdevice.h>
#include <linux/sched.h>
#include <hyperkernel/bfdriverinterface.h>

#ifndef HKD_HANDLER_COUNT
#define HKD_HANDLER_COUNT 2
#endif

/**
 * struct hkd_event_handler
 *
 * @evt[in] the event to handle on behalf of the process
 * @irq the Linux IRQ of the event
 * @task handle of the process to notify
 */
struct hkd_event_handler {
    struct eventfd_ctx *ctx;
    struct task_struct *tsk;
    struct hkd_event evt;
    unsigned int irq;
};

struct hkd_dev {
    struct hkd_event_handler handler[HKD_HANDLER_COUNT];
    struct miscdevice misc;
    const char *name;
};

long hkd_add_event(struct hkd_dev *dev, struct hkd_event __user *evt);
void hkd_free_event_handlers(struct hkd_dev *dev);

#endif
