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

#ifndef EVTCHNOP_INTEL_X64_HYPERKERNEL_H
#define EVTCHNOP_INTEL_X64_HYPERKERNEL_H

#include <mutex>
#include <atomic>

#include "../base.h"
#include "public/event_channel.h"
#include "evtchn.h"
#include "xen_op.h"

#include <eapis/hve/arch/x64/unmapper.h>
#include <bfmath.h>

// -----------------------------------------------------------------------------
// Exports
// -----------------------------------------------------------------------------

#include <bfexports.h>

#ifndef STATIC_HYPERKERNEL_HVE
#ifdef SHARED_HYPERKERNEL_HVE
#define EXPORT_HYPERKERNEL_HVE EXPORT_SYM
#else
#define EXPORT_HYPERKERNEL_HVE IMPORT_SYM
#endif
#else
#define EXPORT_HYPERKERNEL_HVE
#endif

// -----------------------------------------------------------------------------
// Definitions
// -----------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

class vcpu;
class xen_op_handler;

class EXPORT_HYPERKERNEL_HVE evtchn_op
{
public:

    using port_t = evtchn_port_t;
    using word_t = std::atomic<event_word_t>;
    using chan_t = class evtchn;

    using queue_t = struct fifo_queue {
        port_t *head;
        port_t tail;
        uint8_t priority;

        // No locking needed yet
        // std::mutex lock;
    };

    static_assert(is_power_of_2(EVTCHN_FIFO_NR_CHANNELS));
    static_assert(is_power_of_2(sizeof(word_t)));
    static_assert(is_power_of_2(sizeof(chan_t)));

    static_assert(::x64::pt::page_size > sizeof(chan_t));
    static_assert(sizeof(chan_t) > sizeof(word_t));

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param vcpu the vcpu of the evtchn_op
    ///
    evtchn_op(
        gsl::not_null<vcpu *> vcpu,
        gsl::not_null<xen_op_handler *> handler
    );

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~evtchn_op() = default;

    /// Init control
    ///
    void init_control(gsl::not_null<evtchn_init_control_t *> ctl);

    /// Set callback via
    ///
    /// Set the vector used to inject events into the guest
    ///
    void set_callback_via(uint64_t via);

    /// Expand array
    ///
    void expand_array(gsl::not_null<evtchn_expand_array_t *> arr);

    /// Alloc unbound
    ///
    void alloc_unbound(gsl::not_null<evtchn_alloc_unbound_t *> arg);

    /// Send
    ///
    void send(gsl::not_null<evtchn_send_t *> arg);

    /// Bind console
    ///
    port_t bind_console();

    /// Bind store
    ///
    port_t bind_store();

    /// Handle VMX preemption timer
    ///
    void handle_vmx_pet(gsl::not_null<vcpu_t *> vcpu);

private:

    port_t bind_reserved();
    void bind_virq_timer(gsl::not_null<evtchn_bind_virq_t *> bind);

    // Static constants
    //
    static constexpr auto bits_per_xen_ulong = sizeof(xen_ulong_t) * 8;
    static constexpr auto max_channels = EVTCHN_FIFO_NR_CHANNELS;

    static constexpr auto words_per_page = ::x64::pt::page_size / sizeof(word_t);
    static constexpr auto chans_per_page = ::x64::pt::page_size / sizeof(chan_t);
    static constexpr auto max_word_pages = max_channels / words_per_page;
    static constexpr auto max_chan_pages = max_channels / chans_per_page;

    static constexpr auto port_mask = max_channels - 1U;
    static constexpr auto word_mask = words_per_page - 1U;
    static constexpr auto chan_mask = chans_per_page - 1U;

    static constexpr auto word_page_mask = port_mask & ~word_mask;
    static constexpr auto chan_page_mask = port_mask & ~chan_mask;

    static constexpr auto word_page_shift = log2(words_per_page);
    static constexpr auto chan_page_shift = log2(chans_per_page);

    static constexpr auto null_port = 0;

    // Ports
    //
    chan_t *port_to_chan(port_t port) const;
    word_t *port_to_word(port_t port) const;

    uint64_t port_to_chan_page(port_t port) const;
    uint64_t port_to_word_page(port_t port) const;

    port_t make_new_port();
    int make_port(port_t port);
    void setup_ports();
    void setup_control_block(uint64_t gfn, uint32_t offset);

    void make_chan_page(port_t port);
    void make_word_page(gsl::not_null<evtchn_expand_array_t *> expand);

    // Links
    //
    bool set_link(word_t *word, event_word_t *val, port_t link);
    void set_pending(chan_t *chan);

    // Interface for atomic accesses to shared memory
    //
    bool word_is_busy(word_t *word) const;
    bool word_is_linked(word_t *word) const;
    bool word_is_masked(word_t *word) const;
    bool word_is_pending(word_t *word) const;

    void word_set_pending(word_t *word);
    bool word_test_and_set_pending(word_t *word);

    void word_clear_pending(word_t *word);
    bool word_test_and_clear_pending(word_t *word);

    void word_set_busy(word_t *word);
    bool word_test_and_set_busy(word_t *word);

    void word_clear_busy(word_t *word);
    bool word_test_and_clear_busy(word_t *word);

    void word_set_masked(word_t *word);
    bool word_test_and_set_masked(word_t *word);

    void word_clear_masked(word_t *word);
    bool word_test_and_clear_masked(word_t *word);

    void word_set_linked(word_t *word);
    bool word_test_and_set_linked(word_t *word);

    void word_clear_linked(word_t *word);
    bool word_test_and_clear_linked(word_t *word);

    // Data members
    //
    uint64_t m_allocated_chans{};
    uint64_t m_allocated_words{};

    evtchn_fifo_control_block_t *m_ctl_blk{};
    eapis::x64::unique_map<uint8_t> m_ctl_blk_ump{};

    std::array<queue_t, EVTCHN_FIFO_MAX_QUEUES> m_queues{};
    std::array<port_t, NR_VIRQS> m_virq_to_port;

    std::vector<eapis::x64::unique_map<word_t>> m_event_words{};
    std::vector<page_ptr<chan_t>> m_event_chans{};

    vcpu *m_vcpu{};
    xen_op_handler *m_xen_op{};
    uint64_t m_cb_via{};
    port_t m_port_end{1};

public:

    /// @cond

    evtchn_op(evtchn_op &&) = default;
    evtchn_op &operator=(evtchn_op &&) = default;

    evtchn_op(const evtchn_op &) = delete;
    evtchn_op &operator=(const evtchn_op &) = delete;

    /// @endcond
};

}

#endif
