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

set(CMAKE_SYSTEM_NAME Linux)
set(TARGET x86_64-elf CACHE INTERNAL "" FORCE)

# ------------------------------------------------------------------------------
# Quirks
# ------------------------------------------------------------------------------

if(CMAKE_INSTALL_PREFIX)
    set(ENV{CMAKE_INSTALL_PREFIX} "${CMAKE_INSTALL_PREFIX}")
else()
    set(CMAKE_INSTALL_PREFIX "$ENV{CMAKE_INSTALL_PREFIX}")
endif()

if(CLANG_BIN)
    set(ENV{CLANG_BIN} "${CLANG_BIN}")
else()
    set(CLANG_BIN "$ENV{CLANG_BIN}")
endif()

if(LD_BIN)
    set(ENV{LD_BIN} "${LD_BIN}")
else()
    set(LD_BIN "$ENV{LD_BIN}")
endif()

# ------------------------------------------------------------------------------
# Binaries
# ------------------------------------------------------------------------------

if(NOT CLANG_BIN)
    unset(CMAKE_C_COMPILER)
    find_program(CMAKE_C_COMPILER clang)
    unset(CMAKE_CXX_COMPILER)
    find_program(CMAKE_CXX_COMPILER clang)
else()
    set(CMAKE_C_COMPILER ${CLANG_BIN})
    set(CMAKE_CXX_COMPILER ${CLANG_BIN})
endif()

if(NOT LD_BIN)
    set(LD_BIN ${CMAKE_INSTALL_PREFIX}/bin/ld)
endif()

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

string(CONCAT CMAKE_C_FLAGS
    # We define the target here as this is a clang specific feature, and all
    # compiler specific features should be in the toolchain file so that other
    # compilers can be used as well if needed.
    "--target=${TARGET} "

    # These are all of the include folders that an EFI application might need
    # to use. Note that we do not add any Bareflank specific stuff here do you
    # might need to add this by linking to a interface library.
    "-I ${CMAKE_INSTALL_PREFIX}/include/efi "
    "-I ${CMAKE_INSTALL_PREFIX}/include/efi/x86_64 "

    # The following are all of the flags that GNU-EFI uses when compiling its
    # applications. If GNU-EFI is updated, we will need to update this list
    # as well to insure we are up-to-date.
    "-Wno-error=pragmas "
    "-mno-red-zone "
    "-mno-avx "
    "-fpic "
    "-g "
    "-O2 "
    "-Wall "
    "-Wextra "
    "-Werror "
    "-fshort-wchar "
    "-fno-strict-aliasing "
    "-ffreestanding "
    "-fno-stack-protector "
    "-fno-stack-check "
    "-fno-merge-all-constants "
    "--std=c11 "

    # These are all of the definitions that must also be added. Note that we
    # get this by attempting to build the GNU-EFI applications which will spit
    # these out for our system.
    "-DCONFIG_x86_64 "
    "-DGNU_EFI_USE_MS_ABI "
    "-D__KERNEL__ "
    "-DEFI "
)

string(CONCAT CMAKE_PRE_LINK_FLAGS
    # These are all of the linker flags that GNU-EFI uses when compiling its
    # applications. Note that we need to split up the linker command into
    # two sections (pre/post) to ensure linking matches their build system
    "-nostdlib "
    "--warn-common "
    "--no-undefined "
    "--fatal-warnings "
    "--build-id=sha1 "
    "-shared "
    "-Bsymbolic "
    "-L${CMAKE_INSTALL_PREFIX}/lib "
    "${CMAKE_INSTALL_PREFIX}/lib/crt0-efi-x86_64.o "
)

string(CONCAT CMAKE_POST_LINK_FLAGS
    # These are all of the linker flags that GNU-EFI uses when compiling its
    # applications. Note that we need to split up the linker command into
    # two sections (pre/post) to ensure linking matches their build system
    "-lefi "
    "-lgnuefi "
    "-T ${CMAKE_INSTALL_PREFIX}/lib/elf_x86_64_efi.lds "
)

# ------------------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------------------

set(CMAKE_C_ARCHIVE_CREATE
    "ar qc <TARGET> <OBJECTS>"
)

set(CMAKE_C_CREATE_SHARED_LIBRARY
    "ld ${CMAKE_PRE_LINK_FLAGS} <OBJECTS> ${CMAKE_POST_LINK_FLAGS} <LINK_LIBRARIES> -o <TARGET>"
)
