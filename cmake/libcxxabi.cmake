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

message(STATUS "Including dependency: libcxxabi")

# Notes:
#
# When updating Libc++, make sure that the CMake flags are updated as well
# as these change from version to version. This is especially important as
# new features are added to C++ since some of these features will not work
# in a standalone environment like the filesystem, networking and graphics
# addtions.
#

download_dependency(
    libcxxabi
    ${LIBCXXABI_URL}
    ${LIBCXXABI_URL_MD5}
)

list(APPEND LIBCXXABI_CONFIGURE_FLAGS
    # Tell Libc++abi where LLVM and Libc++ is located. This is needed because
    # libc++abi is supposed to be compiled in tree, which we do not do here to
    # save time, so we have to state these manually.
    -DLLVM_PATH=${CACHE_DIR}/llvm
    -DLIBCXXABI_LIBCXX_PATH=${CACHE_DIR}/libcxx

    # Tell CMake where the sysroot is. This not only tells CMake where to
    # install the resulting libraries, it also tells CMake where the include
    # files are.
    -DLIBCXXABI_SYSROOT=${CMAKE_INSTALL_PREFIX}

    # We only support static compilation with standalone c++. As a result, we
    # turn off shared library support and enable static library support.
    -DLIBCXXABI_ENABLE_SHARED=OFF
    -DLIBCXXABI_ENABLE_STATIC=ON

    # Tell libc++abi that we support pthreads. This is needed because libc++
    # will attempt to autodetect pthread support, which will not work since
    # the pthread library compiles after libc++
    -DLIBCXXABI_HAS_PTHREAD_API=ON

    # For some reason, Libc++abi's tests are on by default, which do not
    # support static builds, so we get an error if we do not turn them off
    # manually.
    -DLIBCXXABI_INCLUDE_TESTS=OFF
)

add_dependency(
    libcxxabi
    CMAKE_ARGS  ${LIBCXXABI_CONFIGURE_FLAGS}
    DEPENDS     newlib
)
