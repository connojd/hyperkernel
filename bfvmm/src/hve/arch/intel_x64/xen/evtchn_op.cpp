//
// Bareflank Hyperkernel
// Copyright (C) 2018 Assured Information Security, Inc.
//
// This library is free software; you can redistribute it and/or
// modify it under the terms of the GNU Lesser General Public
// License as published by the Free Software Foundation; either
// version 2.1 of the License, or (at your option) any later version.
//
// This library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public
// License along with this library; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

#include <bfgsl.h>
#include <bfcallonce.h>

#include <errno.h>
#include <string.h>

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/xen/evtchn_op.h>

// =============================================================================
// Implementation
// =============================================================================

static bfn::once_flag g_flag{};

namespace hyperkernel::intel_x64
{

evtchn_op::evtchn_op(
    gsl::not_null<vcpu *> vcpu,
    gsl::not_null<xen_op_handler *> handler)
:
    m_vcpu{vcpu},
    m_xen_op{handler}
{
    m_event_words.reserve(max_word_pages);
    m_event_chans.reserve(max_chan_pages);
}

void
evtchn_op::init_control(gsl::not_null<evtchn_init_control_t *> ctl)
{
    expects(ctl->vcpu == m_vcpu->lapicid());
    expects(ctl->offset <= (0x1000 - sizeof(evtchn_fifo_control_block_t)));
    expects((ctl->offset & 0x7) == 0);

    this->setup_control_block(ctl->control_gfn, ctl->offset);
    this->setup_ports();

    ctl->link_bits = EVTCHN_FIFO_LINK_BITS;
}

void
evtchn_op::set_callback_via(uint64_t via)
{
    expects(m_xen_op->shared_info());

    // At this point, the guest has initialized the evtchn
    // control structures and has just given us the vector
    // to inject whenever an upcall is pending.
    //
    m_cb_via = via;
}

void
evtchn_op::expand_array(gsl::not_null<evtchn_expand_array_t *> arr)
{ this->make_word_page(arr); }

evtchn_op::port_t
evtchn_op::bind_console()
{
    auto port = this->bind_reserved();
    bfdebug_nhex(0, "bound console:", port);
    return port;
}

void
evtchn_op::alloc_unbound(gsl::not_null<evtchn_alloc_unbound_t *> arg)
{
    expects(arg->dom == DOMID_SELF);
    expects(arg->remote_dom == DOMID_SELF);

    auto port = this->make_new_port();
    auto chan = this->port_to_chan(port);

    chan->set_port(port);
    chan->set_state(evtchn::state_unbound);

    arg->port = port;
}

void
evtchn_op::send(gsl::not_null<evtchn_send_t *> arg)
{
    bfdebug_nhex(0, "send port", arg->port);
    this->set_pending(this->port_to_chan(arg->port));
}

evtchn_op::port_t
evtchn_op::bind_store()
{ return this->bind_reserved(); }

// =============================================================================
// Initialization
// =============================================================================

void
evtchn_op::setup_control_block(uint64_t gfn, uint32_t offset)
{
    const auto gpa = gfn << ::x64::pt::page_shift;
    m_ctl_blk_ump = m_vcpu->map_gpa_4k<uint8_t>(gpa);

    uint8_t *base = m_ctl_blk_ump.get() + offset;
    m_ctl_blk = reinterpret_cast<evtchn_fifo_control_block_t *>(base);

    for (auto i = 0; i <= EVTCHN_FIFO_PRIORITY_MIN; i++) {
        m_queues[i].priority = i;
        m_queues[i].head = &m_ctl_blk->head[i];
    }
}

void
evtchn_op::setup_ports()
{
    expects(m_event_words.size() == 0);
    expects(m_event_chans.size() == 0);
    expects(m_allocated_words == 0);
    expects(m_allocated_chans == 0);

    this->make_chan_page(null_port);
    this->port_to_chan(null_port)->set_state(evtchn::state_reserved);

//    for (auto p = 1; p < chans_per_page; p++) {
//        auto arr = m_xen_op->shared_info()->evtchn_pending;
//        auto idx = p / bits_per_xen_ulong;
//        auto bit = p % bits_per_xen_ulong;
//        auto val = arr[idx];
//
//        if (is_bit_set(bit, val)) {
//            this->port_to_chan(p)->set_pending();
//        }
//    }
}

evtchn_op::port_t
evtchn_op::bind_reserved()
{
    const auto port = this->make_new_port();
    auto chan = this->port_to_chan(port);

    //TODO
    chan->set_port(port);
    chan->set_state(evtchn::state_reserved);

    return port;
}

bool
evtchn_op::set_link(word_t *word, event_word_t *val, port_t link)
{
    auto link_bits = (1U << EVTCHN_FIFO_LINKED) | link;
    auto &expect = *val;
    auto desire = (expect & ~((1 << EVTCHN_FIFO_BUSY) | port_mask)) | link_bits;

    return word->compare_exchange_strong(expect, desire);
}

void
evtchn_op::set_pending(chan_t *chan)
{
    expects(m_ctl_blk);

    const auto new_port = chan->port();
    auto new_word = this->port_to_word(new_port);
    if (!new_word) {

        // The guest hasn't added the corresponding
        // event array, so we set pending for later
        //
        bfalert_nhex(0, "port doesn't map to word", new_port);
        chan->set_pending();
        return;
    }

//    const auto was_pending = this->word_test_and_set_pending(new_word);
//    if (this->word_is_masked(new_word) || this->word_is_linked(new_word)) {
//        bfalert_nhex(0, "word_is_masked", this->word_is_masked(new_word));
//        bfalert_nhex(0, "word_is_linked", this->word_is_linked(new_word));
//        return;
//    }

    this->word_set_pending(new_word);
    auto p = chan->priority();
    auto q = &m_queues.at(p);

    // If the queue is empty, insert the tail and signal ready
    if (*q->head == 0) {
        *q->head = new_port;
        q->tail = new_port;

        m_ctl_blk->ready |= (1UL << p);
        ::intel_x64::barrier::wmb();
        m_vcpu->queue_external_interrupt(m_cb_via);

//        bfalert_nhex(0, "q @ p empty, p:", p);
//        bfalert_nhex(0, "new_port:", new_port);
//        bfalert_nhex(0, "ready:", m_ctl_blk->ready);

        return;
    }

    bfalert_nhex(0, "q @ p NON empty, p:", p);

    auto tail_word = this->port_to_word(q->tail);
    auto tail_val = tail_word->load();

    if (!this->set_link(tail_word, &tail_val, new_port)) {
        bfalert_nhex(0, "Failed to set link:", new_port);
        throw std::runtime_error("Failed to set link: " +
                                 std::to_string(new_port));
    }

    q->tail = new_port;
    m_ctl_blk->ready |= (1UL << p);
    ::intel_x64::barrier::wmb();
    m_vcpu->queue_external_interrupt(m_cb_via);
}

// Ports
//
// A port is an address to two things: a chan_t and a word_t
// Ports use a two-level addressing scheme.
//

evtchn_op::port_t
evtchn_op::make_new_port()
{
    for (port_t p = m_port_end; p < max_channels; p++) {
        if (this->make_port(p) == -EBUSY) {
            continue;
        }

        m_port_end = p + 1U;
        return p;
    }

    return null_port;
}

evtchn_op::chan_t *
evtchn_op::port_to_chan(port_t port) const
{
    const auto size = m_event_chans.size();
    const auto page = (port & chan_page_mask) >> chan_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto chan = m_event_chans[page].get();
    return &chan[port & chan_mask];
}

// Note:
//
// Word arrays are shared between the guest and host. The guest adds a new
// word array with the EVTCHNOP_expand_array hypercall, so it is possible
// that a given port doesn't map to an existing event word.
//
evtchn_op::word_t *
evtchn_op::port_to_word(port_t port) const
{
    const auto size = m_event_words.size();
    const auto page = (port & word_page_mask) >> word_page_shift;

    if (page >= size) {
        return nullptr;
    }

    auto word = m_event_words[page].get();
    return &word[port & word_mask];
}

int
evtchn_op::make_port(port_t port)
{
    if (port >= max_channels) {
        throw std::invalid_argument("make_port: port out of range" +
                                    std::to_string(port));
    }

    if (const auto chan = this->port_to_chan(port); chan) {
        if (chan->state() != evtchn::state_free) {
            return -EBUSY;
        }

        auto word = this->port_to_word(port);
        if (word && this->word_is_busy(word)) {
            return -EBUSY;
        }
        return 0;
    }

    this->make_chan_page(port);
    return 0;
}

void
evtchn_op::make_chan_page(port_t port)
{
    const auto indx = (port & chan_page_mask) >> chan_page_shift;
    const auto size = m_event_chans.size();
    const auto cpty = m_event_chans.capacity();

    expects(size == indx);
    expects(size < cpty);

    auto page = make_page<chan_t>();

    for (auto i = 0; i < chans_per_page; i++) {
        auto chan = &page.get()[i];

        chan->set_state(evtchn::state_free);
        chan->set_priority(EVTCHN_FIFO_PRIORITY_DEFAULT);
        chan->set_prev_priority(EVTCHN_FIFO_PRIORITY_DEFAULT);

        //TODO: Need to use ID the guest
        // passes in to bind_virq
        chan->set_vcpuid(0);

        chan->set_prev_vcpuid(0);
        chan->set_port(port + i);
        chan->clear_pending();
    }

    m_event_chans.push_back(std::move(page));
    m_allocated_chans += chans_per_page;
}

void
evtchn_op::make_word_page(gsl::not_null<evtchn_expand_array_t *> expand)
{
    expects(m_event_words.size() < m_event_words.capacity());

    auto prev = m_allocated_words;
    auto addr = expand->array_gfn << ::x64::pt::page_shift;
    auto page = m_vcpu->map_gpa_4k<word_t>(addr);

    m_event_words.push_back(std::move(page));
    m_allocated_words += words_per_page;

    //for (auto p = prev; p < m_allocated_words; p++) {
    //    auto chan = this->port_to_chan(p);
    //    if (!chan || !chan->is_pending()) {
    //        continue;
    //    }
    //    this->set_pending(chan);
    //}
}

bool evtchn_op::word_is_pending(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_PENDING);
}

bool evtchn_op::word_is_masked(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_MASKED);
}

bool evtchn_op::word_is_linked(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_LINKED);
}

bool evtchn_op::word_is_busy(word_t *word) const
{
    return is_bit_set(word->load(), EVTCHN_FIFO_BUSY);
}

void evtchn_op::word_set_pending(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_PENDING);
}

bool evtchn_op::word_test_and_set_pending(word_t *word)
{
    const auto mask = 1U << EVTCHN_FIFO_PENDING;
    const auto prev = word->fetch_or(mask);

    return is_bit_set(prev, EVTCHN_FIFO_PENDING);
}

void evtchn_op::word_set_busy(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_BUSY);
}

bool evtchn_op::word_test_and_set_busy(word_t *word)
{
    const auto mask = 1U << EVTCHN_FIFO_BUSY;
    const auto prev = word->fetch_or(mask);

    return is_bit_set(prev, EVTCHN_FIFO_BUSY);
}

void evtchn_op::word_set_masked(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_MASKED);
}

bool evtchn_op::word_test_and_set_masked(word_t *word)
{
    const auto mask = 1U << EVTCHN_FIFO_MASKED;
    const auto prev = word->fetch_or(mask);

    return is_bit_set(prev, EVTCHN_FIFO_MASKED);
}

void evtchn_op::word_set_linked(word_t *word)
{
    word->fetch_or(1U << EVTCHN_FIFO_LINKED);
}

bool evtchn_op::word_test_and_set_linked(word_t *word)
{
    const auto mask = 1U << EVTCHN_FIFO_LINKED;
    const auto prev = word->fetch_or(mask);

    return is_bit_set(prev, EVTCHN_FIFO_LINKED);
}

void evtchn_op::word_clear_pending(word_t *word)
{
    word->fetch_and(~(1U << EVTCHN_FIFO_PENDING));
}

bool evtchn_op::word_test_and_clear_pending(word_t *word)
{
    const auto mask = ~(1U << EVTCHN_FIFO_PENDING);
    const auto prev = word->fetch_and(mask);

    return is_bit_cleared(prev, EVTCHN_FIFO_PENDING);
}

void evtchn_op::word_clear_busy(word_t *word)
{
    word->fetch_and(~(1U << EVTCHN_FIFO_BUSY));
}

bool evtchn_op::word_test_and_clear_busy(word_t *word)
{
    const auto mask = ~(1U << EVTCHN_FIFO_BUSY);
    const auto prev = word->fetch_and(mask);

    return is_bit_cleared(prev, EVTCHN_FIFO_BUSY);
}

void evtchn_op::word_clear_masked(word_t *word)
{
    word->fetch_and(~(1U << EVTCHN_FIFO_MASKED));
}

bool evtchn_op::word_test_and_clear_masked(word_t *word)
{
    const auto mask = ~(1U << EVTCHN_FIFO_MASKED);
    const auto prev = word->fetch_and(mask);

    return is_bit_cleared(prev, EVTCHN_FIFO_MASKED);
}

void evtchn_op::word_clear_linked(word_t *word)
{
    word->fetch_and(~(1U << EVTCHN_FIFO_LINKED));
}

bool evtchn_op::word_test_and_clear_linked(word_t *word)
{
    const auto mask = ~(1U << EVTCHN_FIFO_LINKED);
    const auto prev = word->fetch_and(mask);

    return is_bit_cleared(prev, EVTCHN_FIFO_LINKED);
}

}
