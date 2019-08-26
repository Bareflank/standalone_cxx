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
# bfdso
# -----------------------------------------------------------------------------

add_library(bfdso
    src/dso/dso.cpp
)

# -----------------------------------------------------------------------------
# bfpthread
# -----------------------------------------------------------------------------

add_library(bfpthread
    src/pthread/pthread.cpp
)

# -----------------------------------------------------------------------------
# bfsyscall
# -----------------------------------------------------------------------------

add_library(bfsyscall
    src/syscall/syscalls.cpp
    $<${INTEL_X64}:src/syscall/arch/x64/syscall.S>
)

# -----------------------------------------------------------------------------
# bfcrt
# -----------------------------------------------------------------------------

# There is a chicken/egg issue with the CRT. It cannot have the stack
# protector becuase it is responsbile for setting this up and it ends
# up in a scenario where it tries to protect itself before it is setup
# resulting in a false positive fail.

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-stack-protector")

add_library(bfcrt
    src/crt/crt.cpp
    $<${INTEL_X64}:src/crt/arch/x64/start.S>
)

# -----------------------------------------------------------------------------
# installs
# -----------------------------------------------------------------------------

install(TARGETS bfdso DESTINATION lib)
install(TARGETS bfpthread DESTINATION lib)
install(TARGETS bfsyscall DESTINATION lib)
install(TARGETS bfcrt DESTINATION lib)
