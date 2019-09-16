#
# Bareflank Hypervisor
# Copyright (C) 2019 Assured Information Security, Inc.
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

cmake_minimum_required(VERSION 3.13)
project(bfruntime CXX ASM)

set(INTEL_X64 $<STREQUAL:${CMAKE_HOST_SYSTEM_PROCESSOR},x86_64>)

# -----------------------------------------------------------------------------
# source
# -----------------------------------------------------------------------------

add_library(bfruntime
    src/dso.cpp
    src/crt.cpp
    src/pthread.cpp
    src/syscalls.cpp
    $<${INTEL_X64}:src/arch/x64/sp.S>
    $<${INTEL_X64}:src/arch/x64/start.S>
    $<${INTEL_X64}:src/arch/x64/syscall.S>
)

# -----------------------------------------------------------------------------
# quirks
# -----------------------------------------------------------------------------

# There is a chicken/egg issue with the CRT. It cannot have the stack
# protector becuase it is responsbile for setting this up and it ends
# up in a scenario where it tries to protect itself before it is setup
# resulting in a false positive fail.

target_compile_options(bfruntime PRIVATE -fno-stack-protector)

# -----------------------------------------------------------------------------
# installs
# -----------------------------------------------------------------------------

install(TARGETS bfruntime DESTINATION lib)
