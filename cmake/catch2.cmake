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

if(CMAKE_BUILD_TYPE MATCHES "Debug")

    message(STATUS "Including dependency: catch2")

    download_dependency(
        catch2
        ${CATCH2_URL}
        ${CATCH2_URL_MD5}
    )

    list(APPEND CATCH2_CONFIGURE_FLAGS
        -DCATCH_BUILD_TESTING=OFF
        -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}
        -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
        -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
        -DCMAKE_BUILD_TYPE=Debug
    )

    if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
        list(APPEND CATCH2_CONFIGURE_FLAGS
            -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
        )
    endif()

    ExternalProject_Add(
        catch2
        CMAKE_ARGS  ${CATCH2_CONFIGURE_FLAGS}
        PREFIX      ${DEPENDS_DIR}/catch2
        STAMP_DIR   ${DEPENDS_DIR}/catch2/stamp
        TMP_DIR     ${DEPENDS_DIR}/catch2/tmp
        BINARY_DIR  ${DEPENDS_DIR}/catch2/build
        LOG_DIR     ${DEPENDS_DIR}/catch2/logs
        SOURCE_DIR  ${CACHE_DIR}/catch2
    )

endif()
