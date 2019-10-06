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
# Targets
# ------------------------------------------------------------------------------

add_custom_target(
    clean-all
    COMMAND ${CMAKE_COMMAND} --build . --target clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_DEPENDS_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_SUBPROJECT_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_EXAMPLE_DIR}
    COMMAND ${CMAKE_COMMAND} -E remove standalone_cxxConfig.cmake
    COMMAND ${CMAKE_COMMAND} -E remove standalone_cxx_sdkConfig.cmake
)

# ------------------------------------------------------------------------------
# Targets
# ------------------------------------------------------------------------------

add_custom_target(
    quick
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexec
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)


add_custom_target(
    test_bfexec_with_custom_heap_size
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexec_with_custom_heap_size
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexec
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexec
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs_no_include_allocations
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexecs_no_include_allocations
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs_with_custom_heap_size
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexecs_with_custom_heap_size
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs_with_custom_heap
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexecs_with_custom_heap
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs_with_manual_allocations
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexecs_with_manual_allocations
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecs
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexecs
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecv_no_optional
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexecv_no_optional
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecv_with_custom_heap_size
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexecv_with_custom_heap_size
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_bfexecv
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexecv
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_empty
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexec
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/empty
)

add_custom_target(
    test_hello_bareflank
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexec
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_bareflank
)

add_custom_target(
    test_hello_world_printf
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexec
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_world_printf
)

add_custom_target(
    test_hello_world
    COMMAND ${BAREFLANK_PREFIX_DIR}/host/bin/bfexec
    ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/bin/hello_world
)
