#
# Copyright (C) 2019 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

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
