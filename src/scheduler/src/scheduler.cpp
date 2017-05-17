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

#include <algorithm>
#include <scheduler/scheduler.h>
#include <debug.h>

scheduler::scheduler(schedulerid::type id) :
    m_id(id)
{ }

void
scheduler::init(user_data *data)
{ (void) data; }

void
scheduler::fini(user_data *data)
{ (void) data; }

void
scheduler::add_task(gsl::not_null<task *> tk)
{ m_tasks.push_back(tk); }

void
scheduler::remove_task(gsl::not_null<task *> tk)
{
    auto &&iter = find(m_tasks.begin(), m_tasks.end(), tk.get());
    m_tasks.erase(iter);
}

void
scheduler::yield()
{
    // TODO:
    //
    // This needs to be updated in several ways:
    //
    // - We need to setup the preemption timer so that we can preempt a task
    //   and move onto another
    // - We need a better algorithm than FCFS
    // - We will need to be able to handle tasks sleeping
    // - We will need to be able to handle task total time, vs thread total
    //   time. Tasks should get 100ms, while a thread should only get 1-10ms.
    //

    if (m_tasks.empty())
        throw std::runtime_error("scheduler is empty");

    if (m_tasks.size() > 1 && m_tasks.front()->num_jobs() == 0)
    {
        bfwarning << "scheduler::yield - m_tasks.size = " << m_tasks.size() << ", num_jobs == 0\n";
        m_tasks.push_back(m_tasks.front());
        m_tasks.pop_front();
    }

    bfwarning << "scheduler::yield calling task::schedule\n";
    m_tasks.front()->schedule();
}

void
scheduler::schedule(thread *thrd, uintptr_t entry, uintptr_t arg1, uintptr_t arg2)
{
    // TODO
    //
    // Need to know what task we should be executing.
    //

    m_tasks.front()->schedule(thrd, entry, arg1, arg2);
}
