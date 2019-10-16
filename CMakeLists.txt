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
project(standalone_cxx NONE)

# ------------------------------------------------------------------------------
# Initial Setup
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/cmake/macros.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/config.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/target.cmake)

# ------------------------------------------------------------------------------
# Interface Library
# ------------------------------------------------------------------------------

setup_interfaces()

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

include_dependency(binutils)
include_dependency(newlib)
include_dependency(llvm)
include_dependency(libcxxabi)
include_dependency(libcxx)
include_dependency(gnuefi)
include_dependency(catch2)

# ------------------------------------------------------------------------------
# Sub Projects
# ------------------------------------------------------------------------------

add_subproject(
    bfsdk           host
    SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/bfsdk
)

add_subproject(
    bfelf_loader    host
    SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/bfelf_loader
)

add_subproject(
    bfsdk           target
    SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/bfsdk
)

add_subproject(
    bfruntime       target
    SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/bfruntime
    DEPENDS         libcxx_target bfsdk_target
)

add_subproject(
    bfunwind        target
    SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/bfunwind
    DEPENDS         libcxx_target bfsdk_target
)

if(NOT BAREFLANK_NOBFCOMPILE)
    add_subproject(
        bfcompile       host
        SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/bfcompile
        DEPENDS         bfsdk_host bfelf_loader_host
    )
endif()

if(BAREFLANK_HOST_BUILD_TYPE MATCHES "Debug")
    add_subproject(
        catch2_main     host
        SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/catch
        DEPENDS         bfsdk_host bfelf_loader_host catch2_host
    )
endif()

# ------------------------------------------------------------------------------
# Examples
# ------------------------------------------------------------------------------

if(NOT BAREFLANK_NOEXAMPLES)
    add_subdirectory(examples)
endif()

# ------------------------------------------------------------------------------
# Quiet Install Command
# ------------------------------------------------------------------------------

install(CODE "MESSAGE(\"Nothing to install\")")
