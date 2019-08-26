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

# ------------------------------------------------------------------------------
# Binaries
# ------------------------------------------------------------------------------

if(NOT DEFINED ENV{CLANG_BIN})
    find_program(CLANG_BIN clang)
else()
    set(CLANG_BIN $ENV{CLANG_BIN})
endif()

if(CLANG_BIN)
    set(CMAKE_C_COMPILER ${CLANG_BIN})
    set(CMAKE_C_COMPILER_WORKS 1)
    set(CMAKE_CXX_COMPILER ${CLANG_BIN})
    set(CMAKE_CXX_COMPILER_WORKS 1)
else()
    message(FATAL_ERROR "Unable to find clang")
endif()

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

unset(CMAKE_C_FLAGS)
unset(CMAKE_C_LINK_FLAGS)

string(CONCAT CMAKE_C_FLAGS
    "--target=x86_64-elf "
    "-fpic "
    "-ffreestanding "
)

string(CONCAT CMAKE_C_LINK_FLAGS
    "-pie "
    "--no-dynamic-linker "
    "-nostdlib "
    "-T ${CMAKE_CURRENT_LIST_DIR}/linker.ld "
)

# ------------------------------------------------------------------------------
# Commands
# ------------------------------------------------------------------------------

set(CMAKE_C_ARCHIVE_CREATE
    "ar qc <TARGET> <OBJECTS>"
)

set(CMAKE_C_LINK_EXECUTABLE
    "ld ${CMAKE_C_LINK_FLAGS} <OBJECTS> -o <TARGET> <LINK_LIBRARIES> -z max-page-size=0x0 -z noexecstack"
)
