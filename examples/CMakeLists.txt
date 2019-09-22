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

list(APPEND TESTS_CXX_ARGN
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE}
    CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
    CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
)

if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    list(APPEND TESTS_CXX_ARGN
        CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
    )
endif()

ExternalProject_Add (
    tests
    ${TESTS_CXX_ARGN}
    DEPENDS             bfruntime bfunwind bfcompile
    PREFIX              ${CMAKE_BINARY_DIR}/examples/tests
    STAMP_DIR           ${CMAKE_BINARY_DIR}/examples/tests/stamp
    TMP_DIR             ${CMAKE_BINARY_DIR}/examples/tests/tmp
    BINARY_DIR          ${CMAKE_BINARY_DIR}/examples/tests/build
    LOG_DIR             ${CMAKE_BINARY_DIR}/examples/tests/logs
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/tests
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
)

# ------------------------------------------------------------------------------
# UEFI
# ------------------------------------------------------------------------------

list(APPEND UEFI_CXX_ARGN
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_LIST_DIR}/uefi/CMakeToolchain.cmake
    CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
    CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
    CMAKE_ARGS -DCXX_FILE_PATH=${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank.bin
    CMAKE_ARGS -DCXX_EF_FILE_PATH=${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank_ef.bin
)

if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    list(APPEND UEFI_CXX_ARGN
        CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
    )
endif()

ExternalProject_Add (
    uefi
    ${UEFI_CXX_ARGN}
    DEPENDS             bfsdk bfelf_loader tests
    PREFIX              ${CMAKE_BINARY_DIR}/examples/uefi
    STAMP_DIR           ${CMAKE_BINARY_DIR}/examples/uefi/stamp
    TMP_DIR             ${CMAKE_BINARY_DIR}/examples/uefi/tmp
    BINARY_DIR          ${CMAKE_BINARY_DIR}/examples/uefi/build
    LOG_DIR             ${CMAKE_BINARY_DIR}/examples/uefi/logs
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/uefi
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
)

# ------------------------------------------------------------------------------
# Loader
# ------------------------------------------------------------------------------

list(APPEND LOADER_CXX_ARGN
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
    CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
    CMAKE_ARGS -DCXX_FILE_PATH=${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank.bin
    CMAKE_ARGS -DCXX_EF_FILE_PATH=${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank_ef.bin
)

if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    list(APPEND LOADER_CXX_ARGN
        CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
    )
endif()

ExternalProject_Add (
    loader
    ${LOADER_CXX_ARGN}
    DEPENDS             bfsdk bfelf_loader tests
    PREFIX              ${CMAKE_BINARY_DIR}/examples/loader
    STAMP_DIR           ${CMAKE_BINARY_DIR}/examples/loader/stamp
    TMP_DIR             ${CMAKE_BINARY_DIR}/examples/loader/tmp
    BINARY_DIR          ${CMAKE_BINARY_DIR}/examples/loader/build
    LOG_DIR             ${CMAKE_BINARY_DIR}/examples/loader/logs
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/loader
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_custom_target(
    quick
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexec
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)


add_custom_target(
    test_bfexec_with_custom_heap_size
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexec_with_custom_heap_size
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexec
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexec
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs_no_include_allocations
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexecs_no_include_allocations
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs_with_custom_heap_size
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexecs_with_custom_heap_size
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs_with_custom_heap
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexecs_with_custom_heap
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs_with_manual_allocations
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexecs_with_manual_allocations
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexecs
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecv_no_optional
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexecv_no_optional
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecv_with_custom_heap_size
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexecv_with_custom_heap_size
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecv
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexecv
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_empty
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexec
    ${CMAKE_INSTALL_PREFIX}/bin/empty
)

add_custom_target(
    test_hello_bareflank
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexec
    ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

add_custom_target(
    test_hello_world_printf
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexec
    ${CMAKE_INSTALL_PREFIX}/bin/hello_world_printf
)

add_custom_target(
    test_hello_world
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/bfexec
    ${CMAKE_INSTALL_PREFIX}/bin/hello_world
)
