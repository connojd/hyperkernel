//
// Bareflank Hyperkernel
//
// Copyright (C) 2015 Assured Information Security, Inc.
// Author: Rian Quinn        <quinnr@ainfosec.com>
// Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
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

#include <exit_handler/exit_handler_intel_x64_hyperkernel.h>

#include <vmcs/vmcs_intel_x64_32bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_32bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_64bit_read_only_data_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_guest_state_fields.h>
#include <vmcs/vmcs_intel_x64_natural_width_read_only_data_fields.h>

#include <domain/domain_manager.h>
#include <domain/domain_intel_x64.h>

#include <process_list_data.h>
#include <vcpu_data_intel_x64.h>
#include <process_data_intel_x64.h>
#include <vmcall_hyperkernel_interface.h>

#include <process/process.h>
#include <process/process_intel_x64.h>

#include <thread/thread.h>
#include <thread/thread_intel_x64.h>

#include <process_list/process_list.h>
#include <process_list/process_list_manager.h>

#include <scheduler/scheduler.h>
#include <scheduler/scheduler_manager.h>

#include <vcpu/vcpu_manager.h>
#include <vcpu/vcpu_intel_x64_hyperkernel.h>

#include <intrinsics/crs_intel_x64.h>

#include <mutex>

std::mutex g_ttys0_mutex;

using namespace x64;
using namespace intel_x64;
using namespace vmcs;

exit_handler_intel_x64_hyperkernel::exit_handler_intel_x64_hyperkernel(
    coreid::type coreid,
    vcpuid::type vcpuid,
    gsl::not_null<process_list *> proclt,
    gsl::not_null<domain_intel_x64 *> domain) :

    m_coreid(coreid),
    m_vcpuid(vcpuid),
    m_proclt(proclt),
    m_domain(domain),
    m_thread(nullptr)
{ }

void
exit_handler_intel_x64_hyperkernel::handle_exit(vmcs::value_type reason)
{
    switch (reason)
    {
        case exit_reason::basic_exit_reason::vm_entry_failure_invalid_guest_state:
        case exit_reason::basic_exit_reason::ept_violation:
        case exit_reason::basic_exit_reason::triple_fault:
        {
            bferror << "guest exited: failure\n";
            bferror << "----------------------------------------------------" << bfendl;
            bferror << "- rip: "
                    << view_as_pointer(m_state_save->rip) << bfendl;
            bferror << "- rsp: "
                    << view_as_pointer(m_state_save->rsp) << bfendl;
            bferror << "- exit reason: "
                    << view_as_pointer(vmcs::exit_reason::get()) << bfendl;
            bferror << "- exit reason string: "
                    << vmcs::exit_reason::basic_exit_reason::description() << bfendl;
            bferror << "- exit qualification: "
                    << view_as_pointer(vmcs::exit_qualification::get()) << bfendl;
            bferror << "- exit interrupt information: "
                    << view_as_pointer(vmcs::vm_exit_interruption_information::get()) << bfendl;
            bferror << "- instruction length: "
                    << view_as_pointer(vmcs::vm_exit_instruction_length::get()) << bfendl;
            bferror << "- instruction information: "
                    << view_as_pointer(vmcs::vm_exit_instruction_information::get()) << bfendl;
            bferror << "- guest linear address: "
                    << view_as_pointer(vmcs::guest_linear_address::get()) << bfendl;
            bferror << "- guest physical address: "
                    << view_as_pointer(vmcs::guest_physical_address::get()) << bfendl;

            g_shm->get_scheduler(m_coreid)->yield();
            break;
        }

        default:
            exit_handler_intel_x64::handle_exit(reason);
            break;
    }
}

void
exit_handler_intel_x64_hyperkernel::create_process_list(vmcall_registers_t &regs)
{
    process_list_data pld;

    if (regs.r03 == domainid::current)
        pld.m_domain = m_domain;
    else
        pld.m_domain = g_dmm->get_domain(regs.r03).get();

    regs.r03 = g_plm->create_process_list(&pld);
}

void
exit_handler_intel_x64_hyperkernel::delete_process_list(vmcall_registers_t &regs)
{
    if (m_proclt->id() == regs.r03)
        throw std::runtime_error("deleting current proclt is not supported");

    g_plm->delete_process_list(regs.r03);
}

void
exit_handler_intel_x64_hyperkernel::create_vcpu(vmcall_registers_t &regs)
{
    vcpu_data_intel_x64 vd;

    if (regs.r03 == processlistid::current)
        vd.m_proclt = m_proclt;
    else
        vd.m_proclt = g_plm->get_process_list(regs.r03).get();

    vd.m_coreid = m_coreid;
    vd.m_domain = dynamic_cast<domain_intel_x64 *>(vd.m_proclt->get_domain().get());

    regs.r03 = vcpu_intel_x64_hyperkernel::next_vcpuid();

    g_vcm->create_vcpu(regs.r03, &vd);
}

void
exit_handler_intel_x64_hyperkernel::delete_vcpu(vmcall_registers_t &regs)
{
    if (m_vcpuid == regs.r03)
        throw std::runtime_error("deleting current vcpu is not supported");

    bfdebug << "total bytes used: " << g_mm->m_total_bytes << "\n";
    g_vcm->delete_vcpu(regs.r03);
}

void
exit_handler_intel_x64_hyperkernel::create_process(vmcall_registers_t &regs)
{
    process_list *proclt;
    process_data_intel_x64 pd;

    if (regs.r03 == processlistid::current)
        proclt = m_proclt;
    else
        proclt = g_plm->get_process_list(regs.r03).get();

    pd.m_domain = m_domain;

    regs.r03 = proclt->create_process(&pd);
}

void
exit_handler_intel_x64_hyperkernel::delete_process(vmcall_registers_t &regs)
{
    process_list *proclt;

    if (regs.r03 == processlistid::current)
        proclt = m_proclt;
    else
        proclt = g_plm->get_process_list(regs.r03).get();

    // FUTURE:
    //
    // Do we need to cleanup m_process? We need to figure out if m_process
    // could end up dangling. Who owns it?
    //

    // FUTURE:
    //
    // Need a generic way to register a driver so that this code has a
    // generic way to cleanup
    //

    if (m_ttys0.m_thread != nullptr && m_ttys0.m_thread->proc()->id() == regs.r04)
        m_ttys0 = {};

    proclt->delete_process(regs.r04);
}

void
exit_handler_intel_x64_hyperkernel::vm_map(vmcall_registers_t &regs)
{
    process_list *proclt;

    // FUTURE:
    //
    // When implementing mmap, we will need a way to identify a range that
    // is allowed to be mapped. Would also be nice to find a way to lookup
    // the current process for this exit handler to know if REG_CURRENT was
    // used. If so, this would still be a foreign vm_map (the memory doesn't
    // belong to the VM to a map is always a foreign call), but we would be
    // able to assert better protections
    //

    if (regs.r03 == processlistid::current)
        proclt = m_proclt;
    else
        proclt = g_plm->get_process_list(regs.r03).get();

    auto &&proc = proclt->get_process(regs.r04);
    proc->vm_map(regs.r05, regs.r06, regs.r07, regs.r08);
}

void
exit_handler_intel_x64_hyperkernel::vm_map_lookup(vmcall_registers_t &regs)
{
    process_list *proclt;

    // FUTURE:
    //
    // When implementing mmap, we will need a way to identify a range that
    // is allowed to be mapped. Would also be nice to find a way to lookup
    // the current process for this exit handler to know if REG_CURRENT was
    // used. If so, this would still be a foreign vm_map (the memory doesn't
    // belong to the VM to a map is always a foreign call), but we would be
    // able to assert better protections
    //

    if (regs.r03 == processlistid::current)
        proclt = m_proclt;
    else
        proclt = g_plm->get_process_list(regs.r03).get();

    auto &&cr3 = vmcs::guest_cr3::get();
    auto &&proc = proclt->get_process(regs.r04);

    proc->vm_map_lookup(regs.r05, cr3, regs.r06, regs.r07, regs.r08);
}

void
exit_handler_intel_x64_hyperkernel::vm_map_lookup_2m(vmcall_registers_t &regs)
{
    process_list *proclt;

    // FUTURE:
    //
    // When implementing mmap, we will need a way to identify a range that
    // is allowed to be mapped. Would also be nice to find a way to lookup
    // the current process for this exit handler to know if REG_CURRENT was
    // used. If so, this would still be a foreign vm_map (the memory doesn't
    // belong to the VM to a map is always a foreign call), but we would be
    // able to assert better protections
    //

    if (regs.r03 == processlistid::current)
        proclt = m_proclt;
    else
        proclt = g_plm->get_process_list(regs.r03).get();

    auto &&cr3 = vmcs::guest_cr3::get();
    auto &&proc = proclt->get_process(regs.r04);

    proc->vm_map_lookup_2m(regs.r05, cr3, regs.r06, regs.r07, regs.r08);
}

void
exit_handler_intel_x64_hyperkernel::set_thread_info(vmcall_registers_t &regs)
{
    process_list *proclt;

    // FUTURE:
    //
    // When implementing set thread info, we should be able to run this
    // without the need for a foreign call. A thread id is not a foreign
    // request as threads are owned by the process. Therefore, if the
    // process list id and the process id are marked REG_CURRENT, this is
    // not a foreign call. If they are marked REG_CURRENT, we will need to
    // get the process id from the scheduler.
    //

    if (regs.r03 == processlistid::current)
        proclt = m_proclt;
    else
        proclt = g_plm->get_process_list(regs.r03).get();

    auto &&proc = proclt->get_process(regs.r04);
    auto &&thrd = proc->get_thread(regs.r05);

    thrd->set_info(regs.r06, regs.r07, regs.r08, regs.r09);
}

void
exit_handler_intel_x64_hyperkernel::sched_yield(vmcall_registers_t &regs)
{
    this->complete_vmcall(BF_VMCALL_SUCCESS, regs);

    if (m_thread != nullptr)
        m_thread->m_state_save = *m_state_save;

    g_shm->get_scheduler(m_coreid)->yield();
}

void
exit_handler_intel_x64_hyperkernel::sched_yield_and_remove(vmcall_registers_t &regs)
{
    expects(m_thread != nullptr);

    m_proclt->remove_process(m_thread->proc()->id());
    sched_yield(regs);
}

void
exit_handler_intel_x64_hyperkernel::set_program_break(vmcall_registers_t &regs)
{
    expects(m_thread != nullptr);

    // TODO
    //
    // Need to implement the foreign calls. This will have to get the proclist
    // and the process to do this
    //

    m_thread->proc()->clear_set_program_break(regs.r05);
}

void
exit_handler_intel_x64_hyperkernel::increase_program_break(vmcall_registers_t &regs)
{
    expects(m_thread != nullptr);

    (void) regs;

    // TODO
    //
    // Need to implement the foreign calls. This will have to get the proclist
    // and the process to do this
    //

    m_thread->proc()->increase_program_break_4k();
}

void
exit_handler_intel_x64_hyperkernel::decrease_program_break(vmcall_registers_t &regs)
{
    expects(m_thread != nullptr);

    (void) regs;

    // TODO
    //
    // Need to implement the foreign calls. This will have to get the proclist
    // and the process to do this
    //

    m_thread->proc()->decrease_program_break_4k();
}

void
exit_handler_intel_x64_hyperkernel::handle_ttys0(vmcall_registers_t &regs)
{
    std::lock_guard<std::mutex> lock(g_ttys0_mutex);

    if (m_ttys0.m_thread == nullptr)
        return handle_ttys1(regs);

    this->complete_vmcall(BF_VMCALL_SUCCESS, regs);
    m_thread->m_state_save = *m_state_save;
    g_shm->get_scheduler(m_coreid)->schedule(m_ttys0.m_thread, m_ttys0.m_entry, regs.r03, 0);
}

void
exit_handler_intel_x64_hyperkernel::handle_ttys1(vmcall_registers_t &regs)
{
    std::cout << gsl::narrow_cast<char>(regs.r03);
}

void
exit_handler_intel_x64_hyperkernel::register_ttys0(vmcall_registers_t &regs)
{
    m_ttys0.m_entry = regs.r03;
    m_ttys0.m_domain = m_domain;
    m_ttys0.m_thread = m_thread;
    m_ttys0.m_proclt = m_proclt.get();
}

void
exit_handler_intel_x64_hyperkernel::handle_vmcall_registers(vmcall_registers_t &regs)
{
    switch (regs.r02)
    {
        case hyperkernel_vmcall__create_process_list:
            create_process_list(regs);
            break;

        case hyperkernel_vmcall__delete_process_list:
            delete_process_list(regs);
            break;

        case hyperkernel_vmcall__create_vcpu:
            create_vcpu(regs);
            break;

        case hyperkernel_vmcall__delete_vcpu:
            delete_vcpu(regs);
            break;

        case hyperkernel_vmcall__create_process:
            create_process(regs);
            break;

        case hyperkernel_vmcall__delete_process:
            delete_process(regs);
            break;

        case hyperkernel_vmcall__vm_map_lookup:
            vm_map_lookup(regs);
            break;

        case hyperkernel_vmcall__vm_map_lookup_2m:
            vm_map_lookup_2m(regs);
            break;

        case hyperkernel_vmcall__set_thread_info:
            set_thread_info(regs);
            break;

        case hyperkernel_vmcall__sched_yield:
            sched_yield(regs);
            break;

        case hyperkernel_vmcall__sched_yield_and_remove:
            sched_yield_and_remove(regs);
            break;

        case hyperkernel_vmcall__set_program_break:
            set_program_break(regs);
            break;

        case hyperkernel_vmcall__increase_program_break:
            increase_program_break(regs);
            break;

        case hyperkernel_vmcall__decrease_program_break:
            decrease_program_break(regs);
            break;

        case hyperkernel_vmcall__ttys0:
            handle_ttys0(regs);
            break;

        case hyperkernel_vmcall__ttys1:
            handle_ttys1(regs);
            break;

        case hyperkernel_vmcall__register_ttys0:
            register_ttys0(regs);
            break;

        default:
            throw std::runtime_error("unknown vmcall: " + std::to_string(regs.r02));
    };
}
