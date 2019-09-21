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

if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_LIST_DIR}/cmake/toolchain/intel_x86_64.cmake)
endif()

project(standalone_cxx NONE)

# ------------------------------------------------------------------------------
# Initial Setup
# ------------------------------------------------------------------------------

include(${CMAKE_CURRENT_LIST_DIR}/cmake/default.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/macros.cmake)

# ------------------------------------------------------------------------------
# Status
# ------------------------------------------------------------------------------

message(STATUS "Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Cache: ${CACHE_DIR}")
message(STATUS "Target: ${TARGET}")
message(STATUS "Toolchain: ${CMAKE_TOOLCHAIN_FILE}")
message(STATUS "Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Heap Size: ${HEAP_SIZE}")
message(STATUS "Stack Size: ${STACK_SIZE}")

# ------------------------------------------------------------------------------
# Compiler Flags
# ------------------------------------------------------------------------------

string(CONCAT CMAKE_FLAGS
    # By default, a compiler's sysroot is hardcoded when the compiler is
    # compiled itself. Since this is a freestanding environment, we must
    # explicitly tell the compiler where our custom sysroot is.
    "--sysroot=${CMAKE_INSTALL_PREFIX} "

    # Tell the compiler that this is a freestanding environment. This ensures
    # that none of the includes from the host system are used, possibly
    # corrupting the build environment.
    "-ffreestanding "

    # This provides additional protections on the stack which is useful as
    # we have to provide our own stack, which means that it can be overrun.
    # If this occurs, this and our canaries can warn the user of the issue.
    "-fstack-protector-strong "

    # This is a bug in clang. For some reason, clang does not define __ELF__,
    # even though the target type ends in ELF. It will only define ELF if it
    # recognizes the operating system portion of the target.
    "-D__ELF__ "

    # For some reason, Libc++ relies on non-standard C functions, so this is
    # needed to ensure these functions are enabled in Newlib so that Libc++
    # can get access to them. We also use gnu instead of std for this reason
    # as we don't want __STRICT_ANSI__ either.
    "-D_GNU_SOURCE "

    # Ensure that we state which POSIX features we support. Normally this is
    # stored in newlib's features.h, but we don't want to patch newlib, so
    # we place this here instead.
    "-D_POSIX_TIMERS "
    "-D_POSIX_THREADS "
    "-D_UNIX98_THREAD_MUTEX_ATTRIBUTES "

    # This is needed due to newlib not supporting long double, which libc++
    # requires. When we turn this on, newlib will provide the missing functions
    # by forwarding them to the double version, which works for now.
    "-D_LDBL_EQ_DBL "

    # This is needed by libc++ as it attempts to detect the OS to determine
    # how the clock is handled, and once it cannot find the OS, since there
    # isn't one, it pukes.
    "-DCLOCK_MONOTONIC "

    # The following defines the heap size that we use. C++ needs a heap for
    # new/delete and malloc/free. To keep things simple, we define a static
    # heap size. If you need a heap that can grow as needed, reimplement the
    # sbrk() function using a custom syscall.
    "-DBFHEAP_SIZE=${HEAP_SIZE} "

    # The following defines the stack size that we use. The entry point for
    # this code will create its own stack, which can be defined by CMake so
    # that downstream projects can redefine this as needed.
    "-DBFSTACK_SIZE=${STACK_SIZE} "
)

if(CMAKE_BUILD_TYPE MATCHES "MinSizeRel")
    string(CONCAT CMAKE_FLAGS
        "${CMAKE_FLAGS} "

        # The following tells the compiler to make sections for all data and
        # functions. Once this is done, the linker can then use these sections
        # to remove code that is not used, reducing overall size.
        "-fdata-sections "
        "-ffunction-sections "
    )
endif()

string(CONCAT CMAKE_C_FLAGS
    "${CMAKE_FLAGS} "
    "${CMAKE_TARGET_C_FLAGS} "

    # Ensure we are compiling with C11 and not the default. Note that we
    # replace "c" with "gnu" which ensures that we do not accidentially
    # define __STRICT_ANSI__ which libc++ does not like.
    "-std=gnu11 "
)

string(CONCAT CMAKE_CXX_FLAGS
    "${CMAKE_FLAGS} "
    "${CMAKE_TARGET_CXX_FLAGS} "

    # Ensure we are compiling with C11 and not the default. Note that we
    # replace "c" with "gnu" which ensures that we do not accidentially
    # define __STRICT_ANSI__ which libc++ does not like.
    "-std=gnu++17 "
)

# ------------------------------------------------------------------------------
# Linker Flags
# ------------------------------------------------------------------------------

string(CONCAT CMAKE_LINK_FLAGS
    # By default, a linkers's sysroot is hardcoded when the linker is
    # compiled itself. Since this is a freestanding environment, we must
    # explicitly tell the linker where our custom sysroot is.
    "--sysroot=${CMAKE_INSTALL_PREFIX} "

    # We only support static pie compilation which means that the result
    # application will be self contained and relocatable. Since shared
    # libraries are not supported, a dynamic linker is not needed as well.
    "-static "
    "-pie "
    "--no-dynamic-linker "

    # Tell the linker that this is a freestanding environment. This ensures
    # that none of the libraries from the host system are used, possibly
    # corrupting the resulting executable.
    "-nostdlib "
)

if(CMAKE_BUILD_TYPE MATCHES "MinSizeRel")
    string(CONCAT CMAKE_LINK_FLAGS
        "${CMAKE_LINK_FLAGS} "

        # The following tells the linker to remove code that is not being used
        # by the application. Note that this only works because we compiled the
        # code using data and function sections.
        "--gc-sections "
        "--strip-all "
    )
endif()

string(CONCAT CMAKE_C_LINK_FLAGS
    "${CMAKE_LINK_FLAGS} "
)

string(CONCAT CMAKE_CXX_LINK_FLAGS
    "${CMAKE_LINK_FLAGS} "
)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_custom_target(
    clean-all
    COMMAND ${CMAKE_COMMAND} --build . --target clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${DEPENDS_DIR}
    USES_TERMINAL
)

# ------------------------------------------------------------------------------
# Interface Library
# ------------------------------------------------------------------------------

setup_interfaces()

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

include_dependency(gnuefi)
include_dependency(binutils)
include_dependency(newlib)
include_dependency(llvm)
include_dependency(libcxxabi)
include_dependency(libcxx)
include_dependency(catch2)

add_subproject(bfsdk ${CMAKE_CURRENT_LIST_DIR}/bfsdk DEPENDS libcxx)
add_subproject(bfruntime ${CMAKE_CURRENT_LIST_DIR}/bfruntime DEPENDS bfsdk)
add_subproject(bfunwind ${CMAKE_CURRENT_LIST_DIR}/bfunwind DEPENDS bfsdk)
add_subproject(bfelf_loader ${CMAKE_CURRENT_LIST_DIR}/bfelf_loader DEPENDS bfsdk)

add_subdirectory(examples)

# ------------------------------------------------------------------------------
# Quiet Install Command
# ------------------------------------------------------------------------------

install(CODE "MESSAGE(\"Nothing to install\")")
