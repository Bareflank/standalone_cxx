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

message(STATUS "Including dependency: newlib")

# TODO
#
# We eventually want to write our own Libc instead of using newlib as newlib
# has some problems:
# - does not compile on Windows as it needs bash
# - it does not fully support Libc++, so we need some hacks to make it
#   work, including long double issues
# - It is a lot larger than we need, and if we want to use C++ in Shellcode,
#   we will need to ensure that the resulting binaries are as small as
#   possible.
# - Newlib itself has a lot of issues with how it was developed, and we would
#   like to add our best practices to how Libc was written to address that
#   including things like enabling all warnings, werror support, static
#   analysis, unit testing, etc.
#
# Also note that we have a step at the end that moves some directories around.
# This is because the GNU tools like to place everyting in "prefix/target",
# and we really want just "prefix" since that is what CMake does.
#

download_dependency(
    newlib
    ${BAREFLANK_NEWLIB_URL}
    ${BAREFLANK_NEWLIB_URL_MD5}
)

list(APPEND BAREFLANK_NEWLIB_CONFIGURE_FLAGS
    # Tell newlib which target we are building for. In general, this step is
    # only needed because this will run on cygwin, and it ensures that we get
    # a library that outputs in ELF.
    --target=${BAREFLANK_TARGET}

    # This tells the compiler where to put the resulting libraries.
    # Note that we will have to modify the results of this as newlib will
    # place the contents in a target folder which we do not want.
    --prefix=${BAREFLANK_PREFIX_DIR}/tmp

    # We do not need libgloss as libgloss is the second half of newlib that
    # adds OS support to newlib. Since we are in a standalone environment,
    # we do not need this step.
    --disable-libgloss

    # Newlib simply will not compile without this as it attempts to set -m32
    # but then doesn't provide 32bit versions of it's assembly logic. This
    # would also make the build longer which we do not want either.
    --disable-multilib

    # Tell newlib what our flags are. Note that this comes from the toolchain
    # file as well as the superbuild CMakeLists.txt and should not be changed
    # as we want the flags to be consistent between all of the libraries.
    CFLAGS_FOR_TARGET=${BAREFLANK_TARGET_CLANG_C_FLAGS}

    # This tells newlib where to fine some binaries that it will need to
    # compile. Since we rely on clang, we do not need target specific versions
    # of these tools so we just use the versions that the host system has
    CC_FOR_TARGET=${BAREFLANK_CLANG_BIN}
    AR_FOR_TARGET=ar
    AS_FOR_TARGET=as
    NM_FOR_TARGET=nm
    OBJCOPY_FOR_TARGET=objcopy
    OBJDUMP_FOR_TARGET=objdump
    RANLIB_FOR_TARGET=ranlib
    READELF_FOR_TARGET=readelf
    STRIP_FOR_TARGET=strip
)

add_dependency(
    newlib              target
    CONFIGURE_COMMAND   ${BAREFLANK_CACHE_DIR}/newlib/configure ${BAREFLANK_NEWLIB_CONFIGURE_FLAGS}
    BUILD_COMMAND       make -j${BAREFLANK_HOST_NUMBER_CORES}
    INSTALL_COMMAND     make install
    DEPENDS             binutils_host
)

add_dependency_step(
    newlib      target
    COMMAND     ${CMAKE_COMMAND} -E copy_directory ${BAREFLANK_PREFIX_DIR}/tmp/${BAREFLANK_TARGET}/lib ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib
    COMMAND     ${CMAKE_COMMAND} -E copy_directory ${BAREFLANK_PREFIX_DIR}/tmp/${BAREFLANK_TARGET}/include ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/include
    COMMAND     ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_PREFIX_DIR}/tmp
)
