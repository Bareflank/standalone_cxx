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

message(STATUS "Including dependency: catch2")

download_dependency(
    catch2
    ${BAREFLANK_CATCH2_URL}
    ${BAREFLANK_CATCH2_URL_MD5}
)

list(APPEND BAREFLANK_CATCH2_CONFIGURE_FLAGS
    -DCATCH_BUILD_TESTING=OFF
)

add_dependency(
    catch2      host
    CMAKE_ARGS  ${BAREFLANK_CATCH2_CONFIGURE_FLAGS}
)

add_dependency_step(
    catch2      host
    COMMAND     ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_PREFIX_DIR}/host/lib64
    COMMAND     ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_PREFIX_DIR}/host/share
)
