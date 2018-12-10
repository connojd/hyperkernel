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

#include <hve/arch/intel_x64/vcpu.h>
#include <hve/arch/intel_x64/ioapic.h>

//--------------------------------------------------------------------------
// Implementation
//--------------------------------------------------------------------------

namespace hyperkernel::intel_x64
{

namespace ioapic_n = ::eapis::intel_x64::ioapic;

ioapic::ioapic(gsl::not_null<vcpu *> vcpu) :
    m_vcpu{vcpu},
    m_ioapic_page{make_page<uint32_t>()},
    m_ioapic_view{m_ioapic_page.get(), 0x1000 / 4}
{ }

void ioapic::init()
{
    auto hpa = g_mm->virtptr_to_physint(m_ioapic_page.get());
    m_vcpu->map_4k_ro(this->base(), hpa);

    this->select(ioapic_n::version::indx);
    this->write(ioapic_n::version::reset_val);

#ifdef NDVM_IOAPIC_ID
    uint32_t id = 0;
    ::intel_x64::ioapic::id::set(id, NDVM_IOAPIC_ID);
    this->select(ioapic_n::id::indx);
    this->write(id);
#else
    #error "NDVM_IOAPIC_ID not defined"
#endif
}

uint32_t ioapic::base() const
{ return IOAPIC_GPA; }

void ioapic::select(uint32_t offset)
{ m_offset = offset; }

uint32_t ioapic::read() const
{ return m_ioapic_view[m_offset]; }

void ioapic::write(uint32_t val)
{ m_ioapic_view[m_offset] = val; }

void ioapic::set_window(uint32_t val)
{
    uint32_t *window = m_ioapic_page.get() + 4;
    *window = val;
}

}
