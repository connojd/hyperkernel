//
// Bareflank Extended APIs
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

#ifndef VMCALL_INTEL_X64_HYPERKERNEL_H
#define VMCALL_INTEL_X64_HYPERKERNEL_H

#include <eapis/hve/arch/intel_x64/base.h>

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

namespace hyperkernel
{
namespace intel_x64
{

class apis;

/// Interrupt window
///
/// Provides an interface for registering handlers of the interrupt-window exit.
///
class EXPORT_HYPERKERNEL_HVE vmcall_handler : public eapis::intel_x64::base
{
public:

    /// Handler delegate type
    ///
    /// The type of delegate clients must use when registering
    /// handlers
    ///
    using handler_delegate_t =
        delegate<bool(gsl::not_null<vmcs_t *>)>;

    #define vmcall_handler_delegate(a,b) \
        vmcall_handler::handler_delegate_t::create<a, &a::b>(this)

    /// Constructor
    ///
    /// @expects
    /// @ensures
    ///
    /// @param apis the apis object for this interrupt window handler
    /// @param hyperkernel_vcpu_state a pointer to the vCPUs global state
    ///
    vmcall_handler(
        gsl::not_null<apis *> apis);

    /// Destructor
    ///
    /// @expects
    /// @ensures
    ///
    ~vmcall_handler() final = default;

public:

    /// Add Handler
    ///
    /// @expects
    /// @ensures
    ///
    /// @param d the handler to call when an exit occurs
    ///
    void add_handler(const handler_delegate_t &d);

public:

    /// Dump Log
    ///
    /// Example:
    /// @code
    /// this->dump_log();
    /// @endcode
    ///
    /// @expects
    /// @ensures
    ///
    void dump_log() final
    { }

public:

    /// @cond

    bool handle(gsl::not_null<vmcs_t *> vmcs);

    /// @endcond

private:

    std::list<handler_delegate_t> m_handlers;

public:

    /// @cond

    vmcall_handler(vmcall_handler &&) = default;
    vmcall_handler &operator=(vmcall_handler &&) = default;

    vmcall_handler(const vmcall_handler &) = delete;
    vmcall_handler &operator=(const vmcall_handler &) = delete;

    /// @endcond
};

}
}

#endif
