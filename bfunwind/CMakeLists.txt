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
project(bfunwind CXX ASM)

set(INTEL_X64 $<STREQUAL:${CMAKE_HOST_SYSTEM_PROCESSOR},x86_64>)

# -----------------------------------------------------------------------------
# bfunwind
# -----------------------------------------------------------------------------

add_library(bfunwind
    src/dwarf4.cpp
    $<${INTEL_X64}:src/eh_frame.cpp>
    $<${INTEL_X64}:src/ia64_cxx_abi.cpp>
    $<${INTEL_X64}:src/arch/intel_x64/registers_intel_x64.S>
)

# -----------------------------------------------------------------------------
# includes
# -----------------------------------------------------------------------------

target_include_directories(bfunwind PUBLIC include)

# -----------------------------------------------------------------------------
# installs
# -----------------------------------------------------------------------------

# Notes
#
# - We have to install the ABI as unwind.h as Libcxx expects this file with
#   this specific filename, but we cannot use this in our own tree as it
#   would collide with the existing unwind.h (and the filename is not very
#   descriptive anyways)
#

install(TARGETS bfunwind DESTINATION lib)
install(FILES include/ia64_cxx_abi.h DESTINATION include RENAME unwind.h)
