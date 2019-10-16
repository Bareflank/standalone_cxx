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
