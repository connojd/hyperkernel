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
# Target Information
################################################################################

TARGET_NAME:=bfcjag
TARGET_TYPE:=bin
TARGET_COMPILER:=cross

SYSROOT_NAME:=vmapp

################################################################################
# Compiler Flags
################################################################################

CROSS_CCFLAGS+=-g -O3 -pthread
CROSS_CXXFLAGS+=
CROSS_ASMFLAGS+=
CROSS_LDFLAGS+=-pie
CROSS_ARFLAGS+=
CROSS_DEFINES+=

################################################################################
# Output
################################################################################

CROSS_OBJDIR+=%BUILD_REL%/.build
CROSS_OUTDIR+=%BUILD_REL%/../bin

################################################################################
# Sources
################################################################################

SOURCES+=detection/paging.c
SOURCES+=detection/cache.c
SOURCES+=detection/cpu.c
SOURCES+=util/error.c
SOURCES+=util/timing.c
SOURCES+=util/colorprint.c
SOURCES+=util/getopt_helper.c
SOURCES+=util/watchdog.c
SOURCES+=cache/evict.c
SOURCES+=cache/set.c
SOURCES+=cache/slice.c
SOURCES+=jag/send.c
SOURCES+=jag/common.c
SOURCES+=jag/receive.c
SOURCES+=cjag.c

INCLUDE_PATHS+=

LIBS+=

LIBRARY_PATHS+=

################################################################################
# Environment Specific
################################################################################

WINDOWS_SOURCES+=
WINDOWS_INCLUDE_PATHS+=
WINDOWS_LIBS+=
WINDOWS_LIBRARY_PATHS+=

LINUX_SOURCES+=
LINUX_INCLUDE_PATHS+=
LINUX_LIBS+=
LINUX_LIBRARY_PATHS+=

################################################################################
# Common
################################################################################

include %HYPER_ABS%/common/common_target.mk
