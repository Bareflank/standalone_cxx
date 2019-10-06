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
# Tests
# ------------------------------------------------------------------------------

add_subproject(
    tests           target
    SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/tests
    DEPENDS         bfruntime_target bfunwind_target
)

# ------------------------------------------------------------------------------
# UEFI
# ------------------------------------------------------------------------------

list(APPEND BAREFLANK_EXAMPLES_UEFI_ARGS
    CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${BAREFLANK_PREFIX_DIR}/CMakeEFIToolchain.cmake
    CMAKE_ARGS -DBAREFLANK_BFCOMPILE=${BAREFLANK_PREFIX_DIR}/host/bin/bfcompile
    CMAKE_ARGS -DBAREFLANK_TESTS_BIN=${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_subproject(
    uefi            target
    SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/uefi
    DEPENDS         bfsdk_host bfelf_loader_host tests_target gnuefi_target
    ${BAREFLANK_EXAMPLES_UEFI_ARGS}
)

# ------------------------------------------------------------------------------
# Loader
# ------------------------------------------------------------------------------

list(APPEND BAREFLANK_EXAMPLES_LOADER_ARGS
    CMAKE_ARGS -DBAREFLANK_BFCOMPILE=${BAREFLANK_PREFIX_DIR}/host/bin/bfcompile
    CMAKE_ARGS -DBAREFLANK_TESTS_BIN=${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_subproject(
    loader          host
    SOURCE_DIR      ${CMAKE_CURRENT_LIST_DIR}/loader
    DEPENDS         bfsdk_host bfelf_loader_host tests_target
    ${BAREFLANK_EXAMPLES_LOADER_ARGS}
)
