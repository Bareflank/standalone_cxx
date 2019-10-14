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

if(NOT BAREFLANK_HOST_BUILD_TYPE)
    set(BAREFLANK_HOST_BUILD_TYPE ${CMAKE_BUILD_TYPE})
endif()

if(NOT BAREFLANK_TARGET_BUILD_TYPE)
    set(BAREFLANK_TARGET_BUILD_TYPE ${CMAKE_BUILD_TYPE})
endif()

# ------------------------------------------------------------------------------
# Processor Count
# ------------------------------------------------------------------------------

include(ProcessorCount)
ProcessorCount(BAREFLANK_HOST_NUMBER_CORES)

# ------------------------------------------------------------------------------
# Cache Directory
# ------------------------------------------------------------------------------

if(NOT BAREFLANK_CACHE_DIR)
    set(BAREFLANK_DEFAULT_CACHE_DIR ${CMAKE_BINARY_DIR}/../cache)

    if(EXISTS ${BAREFLANK_DEFAULT_CACHE_DIR})
        get_filename_component(BAREFLANK_CACHE_DIR "${BAREFLANK_DEFAULT_CACHE_DIR}" ABSOLUTE)
    else()
        set(BAREFLANK_CACHE_DIR ${CMAKE_BINARY_DIR}/cache)
    endif()
endif()

# ------------------------------------------------------------------------------
# Prefix Directory
# ------------------------------------------------------------------------------

if(NOT BAREFLANK_PREFIX_DIR)
    set(BAREFLANK_DEFAULT_PREFIX_DIR ${CMAKE_BINARY_DIR}/../prefix)

    if(EXISTS ${BAREFLANK_DEFAULT_PREFIX_DIR})
        get_filename_component(BAREFLANK_PREFIX_DIR "${BAREFLANK_DEFAULT_PREFIX_DIR}" ABSOLUTE)
    else()
        set(BAREFLANK_PREFIX_DIR ${CMAKE_BINARY_DIR}/prefix)
    endif()
endif()

# ------------------------------------------------------------------------------
# Build Directories
# ------------------------------------------------------------------------------

set(BAREFLANK_DEPENDS_DIR ${CMAKE_BINARY_DIR}/depends)
set(BAREFLANK_SUBPROJECT_DIR ${CMAKE_BINARY_DIR}/sub_projects)
set(BAREFLANK_EXAMPLE_DIR ${CMAKE_BINARY_DIR}/examples)

# ------------------------------------------------------------------------------
# Binaries
# ------------------------------------------------------------------------------

if(NOT BAREFLANK_CLANG_BIN)
    unset(BAREFLANK_CLANG_BIN)
    find_program(BAREFLANK_CLANG_BIN clang)
endif()

if(NOT BAREFLANK_LD_BIN)
    set(BAREFLANK_LD_BIN ${BAREFLANK_PREFIX_DIR}/host/bin/ld)
endif()

# ------------------------------------------------------------------------------
# Definitions
# ------------------------------------------------------------------------------

if(NOT BAREFLANK_HEAP_SIZE)
    set(BAREFLANK_HEAP_SIZE 33554432)
endif()

if(NOT BAREFLANK_STACK_SIZE)
    set(BAREFLANK_STACK_SIZE 32768)
endif()

# ------------------------------------------------------------------------------
# CMake Switches
# ------------------------------------------------------------------------------

set(CMAKE_INSTALL_MESSAGE ALWAYS)
set(CMAKE_TARGET_MESSAGES ${CMAKE_VERBOSE_MAKEFILE})

# ------------------------------------------------------------------------------
# Links
# ------------------------------------------------------------------------------

set(BAREFLANK_BINUTILS_URL "https://ftp.gnu.org/gnu/binutils/binutils-2.32.tar.gz")
set(BAREFLANK_BINUTILS_URL_MD5 "d1119c93fc0ed3007be4a84dd186af55")

set(BAREFLANK_CATCH2_URL "https://github.com/catchorg/Catch2/archive/v2.9.2.zip")
set(BAREFLANK_CATCH2_URL_MD5 "4aee26be3fb0c303c1c4c2f331fd89e4")

set(BAREFLANK_GNUEFI_URL "https://github.com/Bareflank/gnu-efi/archive/v2.0.zip")
set(BAREFLANK_GNUEFI_URL_MD5 "3cd10dc9c14f4a3891f8537fd78ed04f")

set(BAREFLANK_LIBCXX_URL "https://github.com/Bareflank/libcxx/archive/v2.0.2.zip")
set(BAREFLANK_LIBCXX_URL_MD5 "c67639c2a21bf71849df445e1be17bcc")

set(BAREFLANK_LIBCXXABI_URL "https://github.com/Bareflank/libcxxabi/archive/v2.0.2.zip")
set(BAREFLANK_LIBCXXABI_URL_MD5 "10a6fd8c3e3bf056b4a89178919b9d0b")

set(BAREFLANK_LLVM_URL "https://github.com/Bareflank/llvm/archive/v2.0.2.zip")
set(BAREFLANK_LLVM_URL_MD5 "d4a9d94d846c00ce4c1945f998a5af09")

set(BAREFLANK_NEWLIB_URL "https://github.com/Bareflank/newlib/archive/v2.0.2.zip")
set(BAREFLANK_NEWLIB_URL_MD5 "c295aabc581291af4bfad5e56361f43f")

# ------------------------------------------------------------------------------
# Colors
# ------------------------------------------------------------------------------

string(ASCII 27 Esc)
set(ColorReset  "${Esc}[m")
set(ColorBold   "${Esc}[1m")
set(Red         "${Esc}[31m")
set(Green       "${Esc}[32m")
set(Yellow      "${Esc}[33m")
set(Blue        "${Esc}[34m")
set(Magenta     "${Esc}[35m")
set(Cyan        "${Esc}[36m")
set(White       "${Esc}[37m")
set(BoldRed     "${Esc}[1;31m")
set(BoldGreen   "${Esc}[1;32m")
set(BoldYellow  "${Esc}[1;33m")
set(BoldBlue    "${Esc}[1;34m")
set(BoldMagenta "${Esc}[1;35m")
set(BoldCyan    "${Esc}[1;36m")
set(BoldWhite   "${Esc}[1;37m")

# ------------------------------------------------------------------------------
# Toolchain Files
# ------------------------------------------------------------------------------

if(NOT BAREFLANK_TOOLCHAIN_FILE)
    set(BAREFLANK_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/toolchain/intel_x86_64.cmake)
endif()

if(NOT BAREFLANK_EFI_TOOLCHAIN_FILE)
    set(BAREFLANK_EFI_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/toolchain/efi_x86_64.cmake)
endif()

generate_toolchain(${BAREFLANK_TOOLCHAIN_FILE} ${BAREFLANK_PREFIX_DIR}/CMakeToolchain.cmake)
generate_toolchain(${BAREFLANK_EFI_TOOLCHAIN_FILE} ${BAREFLANK_PREFIX_DIR}/CMakeEFIToolchain.cmake)

set(BAREFLANK_TOOLCHAIN_FILE ${BAREFLANK_PREFIX_DIR}/CMakeToolchain.cmake)
set(BAREFLANK_EFI_TOOLCHAIN_FILE ${BAREFLANK_PREFIX_DIR}/CMakeEFIToolchain.cmake)

include(${BAREFLANK_TOOLCHAIN_FILE})
