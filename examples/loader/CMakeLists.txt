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
project(loader CXX ASM)

set(CMAKE_CXX_STANDARD 17)
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
# Loaders
# ------------------------------------------------------------------------------

add_executable(bfexec_no_optional bfexec_no_optional.cpp)
target_link_libraries(bfexec_no_optional PRIVATE standalone_cxx_sdk stdc++fs)
install(TARGETS bfexec_no_optional DESTINATION bin)

add_executable(bfexec_with_custom_heap_size bfexec_with_custom_heap_size.cpp)
target_link_libraries(bfexec_with_custom_heap_size PRIVATE standalone_cxx_sdk stdc++fs)
install(TARGETS bfexec_with_custom_heap_size DESTINATION bin)

add_executable(bfexec bfexec.cpp)
target_link_libraries(bfexec PRIVATE standalone_cxx_sdk stdc++fs)
install(TARGETS bfexec DESTINATION bin)

add_executable(bfexecs_no_include_allocations bfexecs_no_include_allocations.cpp ${CMAKE_BINARY_DIR}/incbin.S)
target_link_libraries(bfexecs_no_include_allocations PRIVATE standalone_cxx_sdk)
target_compile_definitions(bfexecs_no_include_allocations PRIVATE FILENAME="${CMAKE_BINARY_DIR}/test.bin")
target_compile_definitions(bfexecs_no_include_allocations PRIVATE EF_FILENAME="${CMAKE_BINARY_DIR}/test_ef.bin")
install(TARGETS bfexecs_no_include_allocations DESTINATION bin)
add_dependencies(bfexecs_no_include_allocations hello_bareflank)

add_executable(bfexecs_with_custom_heap_size bfexecs_with_custom_heap_size.cpp ${CMAKE_BINARY_DIR}/incbin.S)
target_link_libraries(bfexecs_with_custom_heap_size PRIVATE standalone_cxx_sdk)
target_compile_definitions(bfexecs_with_custom_heap_size PRIVATE FILENAME="${CMAKE_BINARY_DIR}/test.bin")
target_compile_definitions(bfexecs_with_custom_heap_size PRIVATE EF_FILENAME="${CMAKE_BINARY_DIR}/test_ef.bin")
install(TARGETS bfexecs_with_custom_heap_size DESTINATION bin)
add_dependencies(bfexecs_with_custom_heap_size hello_bareflank)

add_executable(bfexecs_with_custom_heap bfexecs_with_custom_heap.cpp ${CMAKE_BINARY_DIR}/incbin.S)
target_link_libraries(bfexecs_with_custom_heap PRIVATE standalone_cxx_sdk)
target_compile_definitions(bfexecs_with_custom_heap PRIVATE FILENAME="${CMAKE_BINARY_DIR}/test.bin")
target_compile_definitions(bfexecs_with_custom_heap PRIVATE EF_FILENAME="${CMAKE_BINARY_DIR}/test_ef.bin")
install(TARGETS bfexecs_with_custom_heap DESTINATION bin)
add_dependencies(bfexecs_with_custom_heap hello_bareflank)

add_executable(bfexecs_with_manual_allocations bfexecs_with_manual_allocations.cpp ${CMAKE_BINARY_DIR}/incbin.S)
target_link_libraries(bfexecs_with_manual_allocations PRIVATE standalone_cxx_sdk)
target_compile_definitions(bfexecs_with_manual_allocations PRIVATE FILENAME="${CMAKE_BINARY_DIR}/test.bin")
target_compile_definitions(bfexecs_with_manual_allocations PRIVATE EF_FILENAME="${CMAKE_BINARY_DIR}/test_ef.bin")
install(TARGETS bfexecs_with_manual_allocations DESTINATION bin)
add_dependencies(bfexecs_with_manual_allocations hello_bareflank)

add_executable(bfexecs bfexecs.cpp ${CMAKE_BINARY_DIR}/incbin.S)
target_link_libraries(bfexecs PRIVATE standalone_cxx_sdk)
target_compile_definitions(bfexecs PRIVATE FILENAME="${CMAKE_BINARY_DIR}/test.bin")
target_compile_definitions(bfexecs PRIVATE EF_FILENAME="${CMAKE_BINARY_DIR}/test_ef.bin")
install(TARGETS bfexecs DESTINATION bin)
add_dependencies(bfexecs hello_bareflank)

add_executable(bfexecv_no_optional bfexecv_no_optional.cpp)
target_link_libraries(bfexecv_no_optional PRIVATE standalone_cxx_sdk stdc++fs)
install(TARGETS bfexecv_no_optional DESTINATION bin)

add_executable(bfexecv_with_custom_heap_size bfexecv_with_custom_heap_size.cpp)
target_link_libraries(bfexecv_with_custom_heap_size PRIVATE standalone_cxx_sdk stdc++fs)
install(TARGETS bfexecv_with_custom_heap_size DESTINATION bin)

add_executable(bfexecv bfexecv.cpp)
target_link_libraries(bfexecv PRIVATE standalone_cxx_sdk stdc++fs)
install(TARGETS bfexecv DESTINATION bin)
