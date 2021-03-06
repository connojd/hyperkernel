#
# Bareflank Hyperkernel
#
# Copyright (C) 2015 Assured Information Security, Inc.
# Author: Rian Quinn        <quinnr@ainfosec.com>
# Author: Brendan Kerrigan  <kerriganb@ainfosec.com>
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA

################################################################################
# Subdirs
################################################################################

PARENT_SUBDIRS += domain
PARENT_SUBDIRS += domain_factory
PARENT_SUBDIRS += entry
PARENT_SUBDIRS += exit_handler
PARENT_SUBDIRS += process
PARENT_SUBDIRS += process_factory
PARENT_SUBDIRS += process_list
PARENT_SUBDIRS += process_list_factory
PARENT_SUBDIRS += scheduler
PARENT_SUBDIRS += scheduler_factory
PARENT_SUBDIRS += task
PARENT_SUBDIRS += thread
PARENT_SUBDIRS += thread_factory
PARENT_SUBDIRS += vcpu
PARENT_SUBDIRS += vcpu_factory
PARENT_SUBDIRS += vmcall_policy
PARENT_SUBDIRS += vmcs

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_subdir.mk
