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
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/mutex.h>
#include <linux/pid.h>

#include <asm/hw_irq.h>

#include <bfdebug.h>
#include <hyperkernel/bfdriverinterface.h>

/**
 * struct hkd_event_handler
 *
 * @param node list_head for list operations
 * @param ctx the context of the eventfd to handle on behalf of the process
 * @param info hardware-specific info for the event's interrupt
 * @param data hardware-specific info for the event's interrupt
 * @param event[in, out] the HKD event. The user supplies the eventfd
 *        as input, and the driver supplies the corresponding physical vector.
 * @param irq the Linux IRQ of the event
 * @param pid the pid of the process listening to this event
 */
struct hkd_event_handler {
    struct list_head node;
    struct eventfd_ctx *efd_ctx;
    struct irq_alloc_info irq_info;
    struct irq_data *irq_data;
    struct hkd_event event;
    unsigned int irq;
    pid_t pid;
};

struct hkd_dev {
    struct list_head event_list;
    struct mutex event_lock;
    struct miscdevice misc;
    const char *name;
};

long hkd_add_event(struct hkd_dev *dev, struct hkd_event __user *evt);
void hkd_free_event_handler(struct hkd_event_handler *handler);
void hkd_release_event_handlers(struct hkd_dev *dev);

#endif
