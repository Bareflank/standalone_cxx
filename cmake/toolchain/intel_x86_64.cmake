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
# Prefix
# ------------------------------------------------------------------------------

if(CMAKE_INSTALL_PREFIX)
    set(ENV{CMAKE_INSTALL_PREFIX} "${CMAKE_INSTALL_PREFIX}")
else()
    set(CMAKE_INSTALL_PREFIX "$ENV{CMAKE_INSTALL_PREFIX}")
endif()

if(NOT CMAKE_INSTALL_PREFIX)
    set(CMAKE_INSTALL_PREFIX ${CMAKE_BINARY_DIR}/prefix CACHE INTERNAL "" FORCE)
endif()

# ------------------------------------------------------------------------------
# Target
# ------------------------------------------------------------------------------

if(TARGET)
    set(ENV{TARGET} "${TARGET}")
else()
    set(TARGET "$ENV{TARGET}")
endif()

if(NOT TARGET)
    set(TARGET x86_64-elf CACHE INTERNAL "" FORCE)
endif()

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

if(DEFINED ENV{LD_BIN})
    set(LD_BIN $ENV{LD_BIN})
else()
    set(LD_BIN ${CMAKE_INSTALL_PREFIX}/bin/ld)
endif()

# ------------------------------------------------------------------------------
# Flags
# ------------------------------------------------------------------------------

string(CONCAT CMAKE_TARGET_C_FLAGS
    # We define the target here as this is a clang specific feature, and all
    # compiler specific features should be in the toolchain file so that other
    # compilers can be used as well if needed.
    "--target=${TARGET} "

    # Intel 64bit requires the use of -fpic as all libraries and executables
    # are compiled as position independent. It is up to the linker to determine
    # if the resulting executable is located at a specific address.
    "-fpic "

    # There really is no need to support CPUs older than Core2 as 64bit support
    # was really not a thing until Core2 anyways. On some compilers, this
    # might not even be needed.
    "-march=core2 "
)

string(CONCAT CMAKE_TARGET_CXX_FLAGS
    # We define the target here as this is a clang specific feature, and all
    # compiler specific features should be in the toolchain file so that other
    # compilers can be used as well if needed.
    "--target=${TARGET} "

    # We define the c++ flag here as this is a clang specific feature, and all
    # compiler specific features should be in the toolchain file so that other
    # compilers can be used as well if needed.
    "-x c++ "

    # Intel 64bit requires the use of -fpic as all libraries and executables
    # are compiled as position independent. It is up to the linker to determine
    # if the resulting executable is located at a specific address.
    "-fpic "

    # There really is no need to support CPUs older than Core2 as 64bit support
    # was really not a thing until Core2 anyways. On some compilers, this
    # might not even be needed.
    "-march=core2 "
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

set(CMAKE_C_LINK_EXECUTABLE
    "${LD_BIN} <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES> -z max-page-size=0x1000 -z noexecstack"
)

set(CMAKE_CXX_LINK_EXECUTABLE
    "${LD_BIN} <LINK_FLAGS> <OBJECTS> -o <TARGET> <LINK_LIBRARIES> -z max-page-size=0x1000 -z noexecstack"
)
