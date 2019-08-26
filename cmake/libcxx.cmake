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

message(STATUS "Including dependency: libcxx")

# Notes:
#
# When updating Libc++, make sure that the CMake flags are updated as well
# as these change from version to version. This is especially important as
# new features are added to C++ since some of these features will not work
# in a standalone environment like the filesystem, networking and graphics
# addtions.
#

download_dependency(
    libcxx
    ${LIBCXX_URL}
    ${LIBCXX_URL_MD5}
)

list(APPEND LIBCXX_CONFIGURE_FLAGS
    # Tell Libc++ where LLVM and Libc++abi is located. This is needed because
    # libc++ is supposed to be compiled in tree, which we do not do here to
    # save time, so we have to state these manually.
    -DLLVM_PATH=${CACHE_DIR}/llvm
    -DLIBCXX_CXX_ABI=libcxxabi
    -DLIBCXX_CXX_ABI_INCLUDE_PATHS=${CACHE_DIR}/libcxxabi/include

    # Tell CMake where the sysroot is. This not only tells CMake where to
    # install the resulting libraries, it also tells CMake where the include
    # files are.
    -DLIBCXX_SYSROOT=${CMAKE_INSTALL_PREFIX}

    # We only support static compilation with standalone c++. As a result, we
    # turn off shared library support and enable static library support.
    -DLIBCXX_ENABLE_SHARED=OFF
    -DLIBCXX_ENABLE_STATIC=ON

    # Tell libc++abi that we support pthreads. This is needed because libc++
    # will attempt to autodetect pthread support, which will not work since
    # the pthread library compiles after libc++
    -DLIBCXX_HAS_PTHREAD_API=ON

    # The remaining flags here are needed to ensure we get the proper C++
    # environment. For example, we want to support atomics, but we do not
    # want to support the filesystem and experimental libraries are they make
    # not sense in a standalone C++ environment.
    -DLIBCXX_HAVE_CXX_ATOMICS_WITHOUT_LIB=ON
    -DLIBCXX_ENABLE_FILESYSTEM=OFF
    -DLIBCXX_ENABLE_EXPERIMENTAL_LIBRARY=OFF
)

add_dependency(
    libcxx
    CMAKE_ARGS  ${LIBCXX_CONFIGURE_FLAGS}
    DEPENDS     libcxxabi
)
