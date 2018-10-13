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

#include <linux/fs.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/miscdevice.h>
#include <linux/notifier.h>
#include <linux/reboot.h>
#include <linux/sched.h>
#include <linux/irq.h>

#include <bfdebug.h>
#include <hyperkernel/bfdriverinterface.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

int g_signum;
struct task_struct *g_task;

/* -------------------------------------------------------------------------- */
/* Misc Device                                                                */
/* -------------------------------------------------------------------------- */

static int
dev_open(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("hkd: dev_open succeeded\n");
    return 0;
}

static int
dev_release(struct inode *inode, struct file *file)
{
    (void) inode;
    (void) file;

    BFDEBUG("hkd: dev_release succeeded\n");
    return 0;
}

static long
ioctl_set_signal(int *signum)
{
    long ret;

    if (signum == 0) {
        BFALERT("hkd: ioctl_set_signal failed with signum == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    ret = copy_from_user(&g_signum, signum, sizeof(int));
    if (ret != 0) {
        BFALERT("ioctl_set_signal: failed to copy memory from userspace\n");
        return BF_IOCTL_FAILURE;
    }

    g_task = current;

    BFDEBUG("hkd: signal: %d\n", g_signum);
    BFDEBUG("hkd: pid: %i\n", g_task->pid);

    return BF_IOCTL_SUCCESS;
}

static long
ioctl_request_irq(void)
{
    long ret;

    int irq = irq_alloc_desc(numa_node_id());
    if (irq < 0) {
        BFALERT("hkd: failed to allocate irq\n");
        return BF_IOCTL_FAILURE;
    }

    BFDEBUG("hkd: irq: %d\n", irq);
    return 0;
}

static long
dev_unlocked_ioctl(struct file *file,
                   unsigned int cmd,
                   unsigned long arg)
{
    (void) file;

    switch (cmd) {
        case HKD_SET_SIGNAL:
            return ioctl_set_signal((int *)arg);

        case HKD_REQUEST_IRQ:
            return ioctl_request_irq();


        default:
            return -ENOTTY;
    }

    return 0;
}

static struct file_operations fops = {
    .open = dev_open,
    .release = dev_release,
    .unlocked_ioctl = dev_unlocked_ioctl,
};

static struct miscdevice hkd_dev = {
    MISC_DYNAMIC_MINOR,
    HKD_NAME,
    &fops
};

/* -------------------------------------------------------------------------- */
/* Entry / Exit                                                               */
/* -------------------------------------------------------------------------- */

int
dev_reboot(struct notifier_block *nb,
           unsigned long code, void *unused)
{
    (void) nb;
    (void) code;
    (void) unused;

    return NOTIFY_DONE;
}

static struct notifier_block hkd_notifier_block = {
    .notifier_call = dev_reboot
};

int
dev_init(void)
{
    register_reboot_notifier(&hkd_notifier_block);

    if (misc_register(&hkd_dev) != 0) {
        BFALERT("misc_register failed\n");
        return -EPERM;
    }

    BFDEBUG("hkd: dev_init succeeded\n");
    return 0;
}

void
dev_exit(void)
{
    misc_deregister(&hkd_dev);
    unregister_reboot_notifier(&hkd_notifier_block);

    BFDEBUG("hkd: dev_exit succeeded\n");
    return;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
