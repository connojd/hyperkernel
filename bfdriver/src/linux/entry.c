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
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/interrupt.h>

#include <bfdebug.h>
#include <bfdriverinterface.h>

#include <hkd/entry.h>

/* -------------------------------------------------------------------------- */
/* Global                                                                     */
/* -------------------------------------------------------------------------- */

uint64_t g_irq;
siginfo_t g_info;
struct task_struct *g_task;

static long ioctl_set_signal(int *sig);
static long ioctl_request_irq(uint64_t *irq);

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
dev_unlocked_ioctl(struct file *file,
                   unsigned int cmd,
                   unsigned long arg)
{
    (void) file;

    switch (cmd) {
        case HKD_SET_SIGNAL:
            return ioctl_set_signal((int *)arg);

        case HKD_REQUEST_IRQ:
            return ioctl_request_irq((uint64_t *)arg);

        default:
            return -EINVAL;
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

static long
ioctl_set_signal(int *sig)
{
    long err;

    if (sig == 0) {
        BFALERT("hkd: ioctl_set_signal failed with signum == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    err = copy_from_user(&g_info.si_signo, sig, sizeof(int));
    if (err) {
        BFALERT("hkd: ioctl_set_signal: failed to copy mem from user\n");
        return BF_IOCTL_FAILURE;
    }

    g_info.si_errno = 0;
    g_info.si_code = SI_KERNEL;

    rcu_read_lock();
    g_task = current;
    rcu_read_unlock();

    BFDEBUG("hkd: ioctl_set_signal: signal: %d\n", *sig);
    return BF_IOCTL_SUCCESS;
}

irqreturn_t handler(int irq, void *hkd_dev)
{
    send_sig_info(g_info.si_signo, &g_info, g_task);
    return IRQ_HANDLED;
}

static long
ioctl_request_irq(uint64_t *irq)
{
    long err;

    if (irq == 0) {
        BFALERT("hkd: ioctl_request_irq failed: with irq == NULL\n");
        return BF_IOCTL_FAILURE;
    }

    err = copy_from_user(&g_irq, irq, sizeof(uint64_t));
    if (err) {
        BFALERT("hkd: ioctl_request_irq: failed to copy mem from user\n");
        return BF_IOCTL_FAILURE;
    }

    if (g_irq < 32 || g_irq > 255) {
        BFALERT("hkd: ioctl_request_irq: irq %llu out of range\n", g_irq);
        g_irq = 0;
        return BF_IOCTL_FAILURE;
    }

    err = request_irq(g_irq, handler, 0, HKD_NAME, &hkd_dev);
    if (err) {
        BFALERT("hkd: ioctl_request_irq: irq %llu not available", g_irq);
        g_irq = 0;
        return BF_IOCTL_FAILURE;
    }


    BFDEBUG("hkd: ioctl_request_irq: succeeded\n");
    return BF_IOCTL_SUCCESS;
}

module_init(dev_init);
module_exit(dev_exit);

MODULE_LICENSE("GPL");
