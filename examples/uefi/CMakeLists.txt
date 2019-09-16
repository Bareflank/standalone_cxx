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
project(cxx_uefi C ASM)

find_package(standalone_cxx_sdk)

add_custom_command(
    OUTPUT ${CMAKE_BINARY_DIR}/cxx_uefi.h
    COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_INSTALL_PREFIX}/bin/hello_bareflank cxx_uefi
    COMMAND xxd -i cxx_uefi > ${CMAKE_INSTALL_PREFIX}/include/efi/cxx_uefi.h
)

add_custom_target(
    cxx_uefi_xxd
    DEPENDS ${CMAKE_BINARY_DIR}/cxx_uefi.h
)

add_library(cxx_uefi SHARED main.c)
add_dependencies(cxx_uefi cxx_uefi_xxd)
target_link_libraries(cxx_uefi PRIVATE standalone_cxx_sdk)

add_custom_command(
    TARGET cxx_uefi
    POST_BUILD
    COMMAND ${CMAKE_OBJCOPY}
    ARGS -j .text -j .sdata -j .data -j .dynamic -j .dynsym
    ARGS -j .rel -j .rela -j .rel.* -j .rela.* -j .rel* -j .rela* -j .reloc
    ARGS --target efi-app-x86_64 libcxx_uefi.so ${CMAKE_BINARY_DIR}/cxx_uefi.efi
)

install(FILES ${CMAKE_BINARY_DIR}/cxx_uefi.efi DESTINATION bin)
