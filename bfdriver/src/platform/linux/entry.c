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

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/irq.h>
#include <linux/interrupt.h>
#include <linux/mm.h>

#include <bfdebug.h>
#include <hyperkernel/bfdriverinterface.h>

#include "hkd.h"

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

struct hkd_dev *g_dev = NULL;

/* -------------------------------------------------------------------------- */
/* File operations                                                            */
/* -------------------------------------------------------------------------- */

static int hkd_open(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    return 0;
}

static int hkd_release(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    hkd_free_event_handlers(g_dev);
    return 0;
}

static long hkd_unlocked_ioctl(struct file *file,
                               unsigned int cmd,
                               unsigned long arg)
{
    (void) file;

    switch (cmd) {
        case HKD_ADD_EVENT_HANDLER:
            return hkd_add_event_handler(g_dev,
                                         (struct hkd_event_handler *)arg);
        default:
            return -ENOTTY;
    }

    return 0;
}

static struct file_operations hkd_fops = {
    .open = hkd_open,
    .release = hkd_release,
    .unlocked_ioctl = hkd_unlocked_ioctl,
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int hkd_init(void)
{
    if (!(g_dev = kzalloc(sizeof(struct hkd_dev), GFP_KERNEL))) {
        return -ENOMEM;
    }

    g_dev->name = HKD_NAME;
    g_dev->misc.minor = MISC_DYNAMIC_MINOR;
    g_dev->misc.name = "hkd";
    g_dev->misc.fops = &hkd_fops;

    if (misc_register(&g_dev->misc)) {
        return -EPERM;
    }

    return 0;
}

void hkd_exit(void)
{
    misc_deregister(&g_dev->misc);
    kfree(g_dev);

    return;
}

module_init(hkd_init);
module_exit(hkd_exit);

MODULE_LICENSE("GPL");
