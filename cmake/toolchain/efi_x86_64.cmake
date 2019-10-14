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

if(NOT BAREFLANK_TARGET)
    set(BAREFLANK_TARGET x86_64-elf CACHE INTERNAL "" FORCE)
endif()

# ------------------------------------------------------------------------------
# Compiler Flags
# ------------------------------------------------------------------------------

string(CONCAT BAREFLANK_CLANG_FLAGS
    "--target=${BAREFLANK_TARGET} "
    "--sysroot=${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET} "
    "-I ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/include/efi "
    "-I ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/include/efi/x86_64 "
    "-mno-red-zone "
    "-mno-avx "
    "-g "
    "-O2 "
    "-Wall "
    "-Wextra "
    "-Werror "
    "-Wno-error=pragmas "
    "-fpic "
    "-fshort-wchar "
    "-fno-strict-aliasing "
    "-ffreestanding "
    "-fno-stack-protector "
    "-fno-stack-check "
    "-fno-merge-all-constants "
    "--std=c11 "
    "-DCONFIG_x86_64 "
    "-DGNU_EFI_USE_MS_ABI "
    "-D__KERNEL__ "
    "-DEFI "
)

# ------------------------------------------------------------------------------
# Linker Flags
# ------------------------------------------------------------------------------

string(CONCAT BAREFLANK_PRE_LD_FLAGS
    "-nostdlib "
    "--warn-common "
    "--no-undefined "
    "--fatal-warnings "
    "--build-id=sha1 "
    "-shared "
    "-Bsymbolic "
    "-L${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib "
    "${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/crt0-efi-x86_64.o "
)

string(CONCAT BAREFLANK_POST_LD_FLAGS
    "-lefi "
    "-lgnuefi "
    "-T ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/elf_x86_64_efi.lds "
)

# ------------------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------------------

set(CMAKE_C_COMPILE_OBJECT
    "${BAREFLANK_CLANG_BIN} ${BAREFLANK_CLANG_FLAGS} <DEFINES> <INCLUDES> -o <OBJECT> -c <SOURCE>"
)

set(CMAKE_C_LINK_EXECUTABLE
    "${BAREFLANK_LD_BIN} ${BAREFLANK_PRE_LD_FLAGS} <OBJECTS> -o <TARGET> ${BAREFLANK_POST_LD_FLAGS}"
)

# ------------------------------------------------------------------------------
# Skip Compiler Checks
# ------------------------------------------------------------------------------

set(CMAKE_C_COMPILER ${BAREFLANK_CLANG_BIN})
set(CMAKE_CXX_COMPILER ${BAREFLANK_CLANG_BIN})

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
