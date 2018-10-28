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
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include <asm/hw_irq.h>
#include <asm/irqdomain.h>

#include <hyperkernel/bfdriverinterface.h>
#include "hkd.h"

/**
 * See arch/x86/kernel/apic/vector.c
 *
 * We really just use the vector, but we need the
 * whole struct so we can do a proper cast from void*
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
 * Event handler
 *
 * Here we simply write to the eventfd to
 * notify userspace an event has arrived
 */
static irqreturn_t hkd_irq_handler(int irq, void *dev_id)
{
    struct hkd_event_handler *eh = dev_id;
    eventfd_signal(eh->efd_ctx, 1);

    return IRQ_HANDLED;
}

/**
 * Initialize a new irq
 *
 * @param info the allocation info containing the affinity mask
 *      of the irq
 * @return the irq_data associated with the irq; NULL on failure
 */
static struct irq_data *
hkd_init_irq_data(struct irq_alloc_info *info)
{
    const int count = 1;
    const int dummy = 42;

    struct irq_domain *dom = x86_vector_domain;
    int irq = irq_create_mapping(dom, dummy);

    if (!irq) {
        return NULL;
    }

    preempt_disable();
    info->mask = cpumask_of(smp_processor_id());
    preempt_enable();

    if (dom->ops->alloc(dom, irq, count, info)) {
        irq_dispose_mapping(irq);
    }

    return irq_get_irq_data(irq);
}

/**
 * DONT CALL THIS
 *
 * dom->ops->free kfree's the apic chip, so subsequent
 * uses point to lala land
 */
static void
hkd_fini_irq_data(struct irq_data *data)
{
    struct irq_domain *dom = x86_vector_domain;

    dom->ops->free(dom, data->irq, 1);
    irq_dispose_mapping(data->irq);
}

/**
 * Allocate and initialize the event handler
 *
 * Note that desc->handle_irq is a "high-level flow handler" that linux
 * provides for common interrupt controller hardware.
 *
 * NOTE: All of these handlers _write_an_EOI_ to the local APIC,
 * so we have to ensure the VMM sends via IPIs instead
 * of VMCS event injection.
 *
 * @param[in,out] event - the hkd_event to init a handler for
 * @return the address of the new event handler; NULL on failure
 */
static struct hkd_event_handler *
hkd_alloc_event_handler(const struct hkd_event *event)
{
    struct hkd_event_handler *eh = NULL;
    struct apic_chip_data *apic = NULL;
    struct eventfd_ctx *ctx = NULL;
    struct irq_desc *desc = NULL;
    struct irq_data *data = NULL;

    eh = kzalloc(sizeof(struct hkd_event_handler), GFP_KERNEL);
    if (!eh) {
        BFALERT("kzalloc error\n");
        return NULL;
    }

    data = hkd_init_irq_data(&eh->irq_info);
    if (!data) {
        BFALERT("hkd_init_irq_data error\n");
        kfree(eh);
        return NULL;
    }

    ctx = eventfd_ctx_fdget(event->eventfd);
    if (IS_ERR(ctx)) {
        BFALERT("eventfd_ctx_fdget error\n");
        hkd_fini_irq_data(data);
        kfree(eh);
        return NULL;
    }

    desc = irq_data_to_desc(data);
    desc->handle_irq = handle_edge_irq;

    apic = data->chip_data;
    eh->event.vector = apic->vector;
    eh->irq = apic->irq;

    eh->pid = current->pid;
    eh->irq_data = data;
    eh->efd_ctx = ctx;

    return eh;
}

/**
 * Free the domain-specific and general
 * resources held by the interrupt
 *
 * @eh the event handler to free
 */
void hkd_free_event_handler(struct hkd_event_handler *eh)
{
    free_irq(eh->irq_data->irq, eh);
    eventfd_ctx_put(eh->efd_ctx);
    hkd_fini_irq_data(eh->irq_data);
    kfree(eh);
}

/**
 * The user supplies the open'd eventfd in user_evt that
 * we will later use to notify the process of an interrupt
 */
long hkd_add_event(struct hkd_dev *dev, struct hkd_event __user *user_evt)
{
    int err;
    struct hkd_event event;
    struct hkd_event_handler *handler = NULL;

    err = copy_from_user(&event, user_evt, sizeof(struct hkd_event));
    if (err) {
        BFALERT("copy_from_user error: %d\n", err);
        return err;
    }

    handler = hkd_alloc_event_handler(&event);
    if (!handler) {
        BFALERT("hkd_alloc_event_handler error\n");
        return -ENOMEM;
    }

    err = request_irq(handler->irq, hkd_irq_handler, 0, HKD_NAME, handler);
    if (err) {
        BFALERT("hkd_request_irq error: %d\n", err);
        hkd_free_event_handler(handler);
        return err;
    }

    err = put_user(handler->event.vector, &user_evt->vector);
    if (err) {
        BFALERT("put_user error: %d\n", err);
        hkd_free_event_handler(handler);
        return err;
    }

    mutex_lock(&dev->event_lock);
    list_add(&handler->node, &dev->event_list);
    mutex_unlock(&dev->event_lock);

    return 0;
}

void hkd_release_event_handlers(struct hkd_dev *dev)
{
    struct hkd_event_handler *eh = NULL;

    mutex_lock(&dev->event_lock);
    list_for_each_entry(eh, &dev->event_list, node) {
        if (eh->pid == current->pid) {
            list_del(&eh->node);
            hkd_free_event_handler(eh);
        }
    }
    mutex_unlock(&dev->event_lock);
}
