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

#include <linux/cpumask.h>
#include <linux/irq.h>
#include <linux/irqdomain.h>
#include <linux/interrupt.h>
#include <linux/pid.h>
#include <linux/printk.h>
#include <linux/sched.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <asm/hw_irq.h>
#include <asm/irqdomain.h>

#include <hyperkernel/bfdriverinterface.h>
#include  "hkd.h"

static struct irq_alloc_info info;
static unsigned int event_count;

/**
 * See arch/x86/kernel/apic/vector.c
 *
 * We really just need the vector, but we include the whole thing
 * so we can do a proper cast from void *
 */
struct apic_chip_data {
	struct irq_cfg		hw_irq_cfg;
	unsigned int		vector;
	unsigned int		prev_vector;
	unsigned int		cpu;
	unsigned int		prev_cpu;
	unsigned int		irq;
	struct hlist_node	clist;
	unsigned int		move_in_progress	: 1,
				is_managed		: 1,
				can_reserve		: 1,
				has_reserved		: 1;
};

/**
 * Handle the irq
 */
static irqreturn_t handler(int irq, void *dev_id)
{
    struct hkd_event_handler *eh = dev_id;

    printk("handling irq (%d): pid: %d eventfd: %d vector: %d irq: %d task: %p",
           irq,
           eh->evt.pid,
           eh->evt.eventfd,
           eh->evt.vector,
           eh->irq,
           eh->tsk);

    eventfd_signal(eh->ctx, 1);
    return IRQ_HANDLED;
}

/**
 * Map and allocate a new irq
 *
 * @return the irq_data associated with the new irq
 */
static struct irq_data *hkd_irq_alloc(void)
{
    const int count = 1;
    const int dummy = 42;
    int irq = 0;
    struct irq_domain *dom = x86_vector_domain;

    irq = irq_create_mapping(dom, dummy);
    if (!irq) {
        return 0;
    }

    info.mask = cpumask_of(smp_processor_id());
    if (dom->ops->alloc(dom, irq, count, &info)) {
        irq_dispose_mapping(irq);
    }

    return irq_get_irq_data(irq);
}

/**
 * Set the handler for the interrupt
 *
 * Note that desc->handle_irq is a "high-level flow handler" that linux
 * provides for common interrupt controller hardware. All of these handlers
 * _write_an_EOI_ to the local APIC, so we have to ensure that we deliver
 * interrupts through the VMM via IPIs instead of VMCS event injection.
 *
 * @data the irq_data of the irq
 * @eh the event handler for this irq
 * @return 0 on success, != 0 otherwise
 */
static int hkd_irq_set_handler(struct irq_data *data,
                               struct hkd_event_handler *eh)
{
    struct eventfd_ctx *ctx = NULL;
    struct pid *pid = find_get_pid(eh->evt.pid);
    struct apic_chip_data *apic = data->chip_data;
    struct irq_desc *desc = irq_data_to_desc(data);

    ctx = eventfd_ctx_fdget(eh->evt.eventfd);
    if (IS_ERR(ctx)) {
        return PTR_ERR(ctx);
    }

    eh->ctx = ctx;
    eh->irq = apic->irq;
    eh->tsk = pid_task(pid, PIDTYPE_PID);
    eh->evt.vector = apic->vector;
    desc->handle_irq = handle_edge_irq;

    return request_irq(eh->irq, handler, 0, HKD_NAME, eh);
}

/**
 * Free domain-specific and general resources of the interrupt
 *
 * @data the irq_data to free
 */
static void hkd_irq_free(struct irq_data *data)
{
    const int count = 1;
    struct irq_domain *dom = x86_vector_domain;

    dom->ops->free(dom, data->irq, count);
    irq_dispose_mapping(data->irq);
}

/**
 * Free the handler itself
 *
 * @data the irq_data to free
 */
static void hkd_irq_free_handler(struct irq_data *data,
                                 struct hkd_event_handler *eh)
{
    eventfd_ctx_put(eh->ctx);
    free_irq(data->irq, eh);
}

long hkd_add_event(struct hkd_dev *dev, struct hkd_event __user *user_evt)
{
    int err;
    struct irq_data *data;
    struct hkd_event *evt;
    struct hkd_event_handler *eh;

    if (event_count >= HKD_HANDLER_COUNT) {
        return -ENOSPC;
    }
    event_count++;

    eh = &dev->handler[event_count - 1];
    evt = &eh->evt;
    err = copy_from_user(evt, user_evt, sizeof(struct hkd_event));
    if (err) {
        BFALERT("copy_from_user failed: %d\n", err);
        goto subtract;
    }

    data = hkd_irq_alloc();
    if (!data) {
        BFALERT("hkd_irq_alloc failed");
        err = -ENOMEM;
        goto subtract;
    }

    err = hkd_irq_set_handler(data, eh);
    if (err) {
        BFALERT("hkd_irq_set_handler failed: %d\n", err);
        goto free_irq;
    }

    BFDEBUG("%s: pid: %d eventfd: %d vector: %d\n",
            __func__,
            eh->evt.pid,
            eh->evt.eventfd,
            eh->evt.vector);

    err = put_user(eh->evt.vector, &user_evt->vector);
    if (err) {
        BFALERT("put_user failed");
        goto free_handler;
    }

    return 0;

free_handler:
    hkd_irq_free_handler(data, eh);
free_irq:
    hkd_irq_free(data);
subtract:
    event_count--;
    return err;
}

void hkd_free_event_handlers(struct hkd_dev *dev)
{
    int i;
    struct irq_data *data;
    struct hkd_event_handler *eh;

    for (i = 0; i < HKD_HANDLER_COUNT; ++i) {

        if (!dev->handler[i].irq) {
            continue;
        }

        eh = &dev->handler[i];
        data = irq_get_irq_data(eh->irq);
        hkd_irq_free_handler(data, eh);
        hkd_irq_free(data);
    }
}
