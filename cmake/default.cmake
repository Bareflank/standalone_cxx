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

# ------------------------------------------------------------------------------
# Build Type
# ------------------------------------------------------------------------------

if (NOT CMAKE_BUILD_TYPE MATCHES "Release" AND NOT CMAKE_BUILD_TYPE MATCHES "Debug")
    set(CMAKE_BUILD_TYPE "MinSizeRel")
endif()

# ------------------------------------------------------------------------------
# Processor Count
# ------------------------------------------------------------------------------

include(ProcessorCount)
ProcessorCount(HOST_NUMBER_CORES)

# ------------------------------------------------------------------------------
# Cache Directory
# ------------------------------------------------------------------------------

set(DEFAULT_CACHE_DIR ${CMAKE_SOURCE_DIR}/../cache)

if(EXISTS ${DEFAULT_CACHE_DIR})
    get_filename_component(CACHE_DIR "${DEFAULT_CACHE_DIR}" ABSOLUTE)
else()
    set(CACHE_DIR ${CMAKE_BINARY_DIR}/cache CACHE INTERNAL "" FORCE)
endif()

# ------------------------------------------------------------------------------
# Depends Directory
# ------------------------------------------------------------------------------

set(DEPENDS_DIR ${CMAKE_BINARY_DIR}/depends CACHE INTERNAL "" FORCE)

# ------------------------------------------------------------------------------
# Prefix Directory
# ------------------------------------------------------------------------------

set(DEFAULT_PREFIX_DIR ${CMAKE_SOURCE_DIR}/../prefix)

if(EXISTS ${DEFAULT_PREFIX_DIR})
    get_filename_component(CMAKE_INSTALL_PREFIX "${DEFAULT_PREFIX_DIR}" ABSOLUTE)
else()
    set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/prefix CACHE INTERNAL "" FORCE)
endif()

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

if(NOT HEAP_SIZE)
    set(HEAP_SIZE 33554432 CACHE INTERNAL "" FORCE)
endif()

if(NOT STACK_SIZE)
    set(STACK_SIZE 32768 CACHE INTERNAL "" FORCE)
endif()

# ------------------------------------------------------------------------------
# CMake Switches
# ------------------------------------------------------------------------------

set(CMAKE_INSTALL_MESSAGE ALWAYS CACHE INTERNAL "" FORCE)
set(CMAKE_TARGET_MESSAGES ${CMAKE_VERBOSE_MAKEFILE} CACHE INTERNAL "" FORCE)

# ------------------------------------------------------------------------------
# Links
# ------------------------------------------------------------------------------

set(BINUTILS_URL "https://ftp.gnu.org/gnu/binutils/binutils-2.32.tar.gz" CACHE INTERNAL "" FORCE)
set(BINUTILS_URL_MD5 "d1119c93fc0ed3007be4a84dd186af55" CACHE INTERNAL "" FORCE)

set(CATCH2_URL "https://github.com/catchorg/Catch2/archive/v2.9.2.zip" CACHE INTERNAL "" FORCE)
set(CATCH2_URL_MD5 "4aee26be3fb0c303c1c4c2f331fd89e4" CACHE INTERNAL "" FORCE)

set(GNUEFI_URL "https://github.com/Bareflank/gnu-efi/archive/v2.0.zip" CACHE INTERNAL "" FORCE)
set(GNUEFI_URL_MD5 "3cd10dc9c14f4a3891f8537fd78ed04f" CACHE INTERNAL "" FORCE)

set(LIBCXX_URL "https://github.com/Bareflank/libcxx/archive/v2.0.2.zip" CACHE INTERNAL "" FORCE)
set(LIBCXX_URL_MD5 "c67639c2a21bf71849df445e1be17bcc" CACHE INTERNAL "" FORCE)

set(LIBCXXABI_URL "https://github.com/Bareflank/libcxxabi/archive/v2.0.2.zip" CACHE INTERNAL "" FORCE)
set(LIBCXXABI_URL_MD5 "10a6fd8c3e3bf056b4a89178919b9d0b" CACHE INTERNAL "" FORCE)

set(LLVM_URL "https://github.com/Bareflank/llvm/archive/v2.0.2.zip" CACHE INTERNAL "" FORCE)
set(LLVM_URL_MD5 "d4a9d94d846c00ce4c1945f998a5af09" CACHE INTERNAL "" FORCE)

set(NEWLIB_URL "https://github.com/Bareflank/newlib/archive/v2.0.2.zip" CACHE INTERNAL "" FORCE)
set(NEWLIB_URL_MD5 "c295aabc581291af4bfad5e56361f43f" CACHE INTERNAL "" FORCE)
