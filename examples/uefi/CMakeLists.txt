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
project(uefi_app C ASM)

find_package(standalone_cxx_sdk)

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

file(COPY ${CMAKE_CURRENT_LIST_DIR}/incbin.S DESTINATION ${CMAKE_BINARY_DIR})

add_custom_command(OUTPUT ${CMAKE_BINARY_DIR}/test.bin
    COMMAND ${BAREFLANK_BFCOMPILE} ${BAREFLANK_TESTS_BIN} ${CMAKE_BINARY_DIR}/test.bin ${CMAKE_BINARY_DIR}/test_ef.bin
    COMMAND ${CMAKE_COMMAND} -E remove ${CMAKE_BINARY_DIR}/incbin.S
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_LIST_DIR}/incbin.S ${CMAKE_BINARY_DIR}/incbin.S
    DEPENDS ${BAREFLANK_TESTS_BIN}
)

add_custom_target(
    hello_bareflank
    DEPENDS ${CMAKE_BINARY_DIR}/test.bin
)

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------

add_library(uefi_app SHARED main.c ${CMAKE_BINARY_DIR}/incbin.S)
target_link_libraries(uefi_app PRIVATE standalone_cxx_sdk)
target_compile_definitions(uefi_app PRIVATE FILENAME="${CMAKE_BINARY_DIR}/test.bin")
target_compile_definitions(uefi_app PRIVATE EF_FILENAME="${CMAKE_BINARY_DIR}/test_ef.bin")
add_dependencies(uefi_app hello_bareflank)

add_custom_command(
    TARGET uefi_app
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY}
    ARGS -j .text -j .sdata -j .data -j .dynamic -j .dynsym
    ARGS -j .rel -j .rela -j .rel.* -j .rela.* -j .rel* -j .rela* -j .reloc
    ARGS --target efi-app-x86_64 libuefi_app.so ${CMAKE_BINARY_DIR}/uefi_app.efi
)

install(FILES ${CMAKE_BINARY_DIR}/uefi_app.efi DESTINATION bin)
