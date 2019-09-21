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
# File Compare
# ------------------------------------------------------------------------------

list(APPEND FILECMP_CXX_ARGN
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
    CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Debug
)

if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    list(APPEND FILECMP_CXX_ARGN
        CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
    )
endif()

ExternalProject_Add (
    filecmp
    ${FILECMP_CXX_ARGN}
    PREFIX              ${CMAKE_BINARY_DIR}/examples/filecmp
    STAMP_DIR           ${CMAKE_BINARY_DIR}/examples/filecmp/stamp
    TMP_DIR             ${CMAKE_BINARY_DIR}/examples/filecmp/tmp
    BINARY_DIR          ${CMAKE_BINARY_DIR}/examples/filecmp/build
    LOG_DIR             ${CMAKE_BINARY_DIR}/examples/filecmp/logs
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/filecmp
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
)

# ------------------------------------------------------------------------------
# Payload
# ------------------------------------------------------------------------------

list(APPEND PAYLOAD_CXX_ARGN
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${CMAKE_CURRENT_LIST_DIR}/payload/CMakeToolchain.cmake
    CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
    CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=MinSizeRel
    CMAKE_ARGS -DCXX_PAYLOAD_PATH=${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
)

if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    list(APPEND PAYLOAD_CXX_ARGN
        CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
    )
endif()

ExternalProject_Add (
    payload
    ${PAYLOAD_CXX_ARGN}
    DEPENDS             bfsdk bfelf_loader
    PREFIX              ${CMAKE_BINARY_DIR}/examples/payload
    STAMP_DIR           ${CMAKE_BINARY_DIR}/examples/payload/stamp
    TMP_DIR             ${CMAKE_BINARY_DIR}/examples/payload/tmp
    BINARY_DIR          ${CMAKE_BINARY_DIR}/examples/payload/build
    LOG_DIR             ${CMAKE_BINARY_DIR}/examples/payload/logs
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/payload
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
)

# ------------------------------------------------------------------------------
# Compile
# ------------------------------------------------------------------------------

list(APPEND COMPILE_CXX_ARGN
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
    CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=Release
)

if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    list(APPEND COMPILE_CXX_ARGN
        CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
    )
endif()

ExternalProject_Add (
    compile
    ${COMPILE_CXX_ARGN}
    DEPENDS             bfsdk bfelf_loader filecmp payload
    PREFIX              ${CMAKE_BINARY_DIR}/examples/compile
    STAMP_DIR           ${CMAKE_BINARY_DIR}/examples/compile/stamp
    TMP_DIR             ${CMAKE_BINARY_DIR}/examples/compile/tmp
    BINARY_DIR          ${CMAKE_BINARY_DIR}/examples/compile/build
    LOG_DIR             ${CMAKE_BINARY_DIR}/examples/compile/logs
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/compile
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
)

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
    DEPENDS             bfruntime bfunwind compile
    PREFIX              ${CMAKE_BINARY_DIR}/examples/tests
    STAMP_DIR           ${CMAKE_BINARY_DIR}/examples/tests/stamp
    TMP_DIR             ${CMAKE_BINARY_DIR}/examples/tests/tmp
    BINARY_DIR          ${CMAKE_BINARY_DIR}/examples/tests/build
    LOG_DIR             ${CMAKE_BINARY_DIR}/examples/tests/logs
    SOURCE_DIR          ${CMAKE_CURRENT_LIST_DIR}/tests
    UPDATE_COMMAND      cmake -E echo -- Checking for changes
)

# ------------------------------------------------------------------------------
# Loader
# ------------------------------------------------------------------------------

list(APPEND LOADER_CXX_ARGN
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
    CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
    CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
    CMAKE_ARGS -DCMAKE_BUILD_TYPE=MinSizeRel
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
# Targets
# ------------------------------------------------------------------------------

add_custom_target(
    quick
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/loader_from_file ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank
    USES_TERMINAL
)

add_custom_target(
    quick_embedded
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/loader_from_embedded
    USES_TERMINAL
)

add_custom_target(
    quick_payload
    COMMAND echo 0 | sudo tee /proc/sys/kernel/randomize_va_space > /dev/null
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/filecmp ${CMAKE_INSTALL_PREFIX}/bin/payload.bin ${CMAKE_INSTALL_PREFIX}/bin/test.txt
    USES_TERMINAL
)

add_custom_target(
    test_empty
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/loader_from_file ${CMAKE_INSTALL_PREFIX}/bin/empty
    USES_TERMINAL
)

add_custom_target(
    test_hello_world
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/loader_from_file ${CMAKE_INSTALL_PREFIX}/bin/hello_world
    USES_TERMINAL
)

add_custom_target(
    test_hello_world_printf
    COMMAND ${CMAKE_INSTALL_PREFIX}/bin/loader_from_file ${CMAKE_INSTALL_PREFIX}/bin/hello_world_printf
    USES_TERMINAL
)
