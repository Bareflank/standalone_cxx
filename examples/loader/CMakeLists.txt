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

add_executable(loader_from_file loader_from_file.cpp)
target_link_libraries(loader_from_file PRIVATE standalone_cxx_sdk)
install(TARGETS loader_from_file DESTINATION bin)

add_executable(loader_from_embedded loader_from_embedded.cpp incbin.S)
target_link_libraries(loader_from_embedded PRIVATE standalone_cxx_sdk)
target_compile_definitions(loader_from_embedded PRIVATE FILENAME="${CXX_FILE_PATH}")
target_compile_definitions(loader_from_embedded PRIVATE EF_FILENAME="${CXX_EF_FILE_PATH}")
install(TARGETS loader_from_embedded DESTINATION bin)
