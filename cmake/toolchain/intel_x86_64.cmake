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
set(BAREFLANK_TARGET x86_64-elf CACHE INTERNAL "" FORCE)

# ------------------------------------------------------------------------------
# Compiler Flags
# ------------------------------------------------------------------------------

string(CONCAT BAREFLANK_TARGET_CLANG_FLAGS
    "--target=${BAREFLANK_TARGET} "
    "--sysroot=${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET} "
    "-isystem ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/include/c++/v1 "
    "-isystem ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/include "
    "-isystem ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/include/bfsdk "
    "-c "
    "-fPIC "
    "-ffreestanding "
    "-fstack-protector-strong "
    "-march=core2 "
    "-Wno-constant-conversion "
    "-D__ELF__ "
    "-D_GNU_SOURCE "
    "-D_POSIX_TIMERS "
    "-D_POSIX_THREADS "
    "-D_UNIX98_THREAD_MUTEX_ATTRIBUTES "
    "-D_LDBL_EQ_DBL "
    "-DCLOCK_MONOTONIC "
    "-DBFHEAP_SIZE=${BAREFLANK_HEAP_SIZE} "
    "-DBFSTACK_SIZE=${BAREFLANK_STACK_SIZE} "
)

if(${BAREFLANK_TARGET_BUILD_TYPE} MATCHES "MinSizeRel")
    string(CONCAT BAREFLANK_TARGET_CLANG_FLAGS
        "-Os "
        "-DNDEBUG "
        "${BAREFLANK_TARGET_CLANG_FLAGS}"
    )
elseif(${BAREFLANK_TARGET_BUILD_TYPE} MATCHES "Release")
    string(CONCAT BAREFLANK_TARGET_CLANG_FLAGS
        "-O2 "
        "-DNDEBUG "
        "${BAREFLANK_TARGET_CLANG_FLAGS}"
    )
elseif(${BAREFLANK_TARGET_BUILD_TYPE} MATCHES "Debug")
    string(CONCAT BAREFLANK_TARGET_CLANG_FLAGS
        "-g "
        "${BAREFLANK_TARGET_CLANG_FLAGS}"
    )
endif()

string(CONCAT BAREFLANK_TARGET_CLANG_C_FLAGS
    "-std=gnu11 "
    "${BAREFLANK_TARGET_C_FLAGS}"
    "${BAREFLANK_TARGET_CLANG_FLAGS}"
)

string(CONCAT BAREFLANK_TARGET_CLANG_CXX_FLAGS
    "-x c++ "
    "-std=gnu++17 "
    "${BAREFLANK_TARGET_CXX_FLAGS}"
    "${BAREFLANK_TARGET_CLANG_FLAGS}"
)

# ------------------------------------------------------------------------------
# Linker Flags
# ------------------------------------------------------------------------------

string(CONCAT BAREFLANK_TARGET_LD_FLAGS
    "--sysroot=${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET} "
    "-static "
    "-pie "
    "--no-dynamic-linker "
    "-nostdlib "
    "-z max-page-size=0x1000 "
    "-z noexecstack "
)

string(CONCAT BAREFLANK_TARGET_LD_C_FLAGS
    "${BAREFLANK_TARGET_LINK_FLAGS}"
    "${BAREFLANK_TARGET_LD_FLAGS}"
)

string(CONCAT BAREFLANK_TARGET_LD_CXX_FLAGS
    "${BAREFLANK_TARGET_LINK_FLAGS}"
    "${BAREFLANK_TARGET_LD_FLAGS}"
)

# ------------------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------------------

set(CMAKE_C_ARCHIVE_CREATE
    "ar qc <TARGET> <OBJECTS>"
)

set(CMAKE_CXX_ARCHIVE_CREATE
    "ar qc <TARGET> <OBJECTS>"
)

set(CMAKE_C_COMPILE_OBJECT
    "${BAREFLANK_CLANG_BIN} ${BAREFLANK_TARGET_CLANG_C_FLAGS} <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>"
)

set(CMAKE_CXX_COMPILE_OBJECT
    "${BAREFLANK_CLANG_BIN} ${BAREFLANK_TARGET_CLANG_CXX_FLAGS} <DEFINES> <INCLUDES> <FLAGS> -o <OBJECT> -c <SOURCE>"
)

set(CMAKE_C_LINK_EXECUTABLE
    "${BAREFLANK_LD_BIN} ${BAREFLANK_TARGET_LD_C_FLAGS} <CMAKE_C_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
)

set(CMAKE_CXX_LINK_EXECUTABLE
    "${BAREFLANK_LD_BIN} ${BAREFLANK_TARGET_LD_CXX_FLAGS} <CMAKE_CXX_LINK_FLAGS> <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES>"
)

# ------------------------------------------------------------------------------
# Skip Compiler Checks
# ------------------------------------------------------------------------------

set(CMAKE_C_COMPILER ${BAREFLANK_CLANG_BIN})
set(CMAKE_CXX_COMPILER ${BAREFLANK_CLANG_BIN})

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)
