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
#include <linux/list.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/mutex.h>

#include <bfdebug.h>
#include <hyperkernel/bfdriverinterface.h>

#include "hkd.h"

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

static struct hkd_dev g_dev;

/* -------------------------------------------------------------------------- */
/* File operations                                                            */
/* -------------------------------------------------------------------------- */

static int hkd_open(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("%s: success", __func__);
    return 0;
}

static int hkd_release(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    hkd_release_event_handlers(&g_dev);
    BFDEBUG("%s: success", __func__);

    return 0;
}

static long hkd_unlocked_ioctl(struct file *file,
                               unsigned int cmd,
                               unsigned long arg)
{
    (void) file;

    switch (cmd) {
        case HKD_ADD_EVENT:
            return hkd_add_event(&g_dev, (struct hkd_event *)arg);
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
    INIT_LIST_HEAD(&g_dev.event_list);
    mutex_init(&g_dev.event_lock);

    g_dev.name = HKD_NAME;
    g_dev.misc.name = HKD_NAME;
    g_dev.misc.fops = &hkd_fops;
    g_dev.misc.minor = MISC_DYNAMIC_MINOR;

    if (misc_register(&g_dev.misc)) {
        return -EPERM;
    }

    return 0;
}

void hkd_exit(void)
{
    struct hkd_event_handler *eh = NULL;

    list_for_each_entry(eh, &g_dev.event_list, node) {
        list_del(&eh->node);
        hkd_free_event_handler(eh);
    }

    misc_deregister(&g_dev.misc);
    return;
}

module_init(hkd_init);
module_exit(hkd_exit);

MODULE_LICENSE("GPL");
