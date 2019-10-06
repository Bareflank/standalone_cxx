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

message(STATUS "Including dependency: binutils")

# TODO
#
# In the future we would like to switch from binutils to lld. The reason we
# have not done this yet is we need Cygwin to support lld natively, with
# support for changing the target (similar to how clang works today). Once
# this is done, we should be able to cross-compile on Linux and Windows
# without the need for compiling our own binutils.
#
# It should be noted that once this is done, the ELF loader might need and
# update as the sections that each ELF file has is determined by the linker,
# and in the past, lld was not using the same init/fini sections as ld.
#
# Also note that we have a step at the end that moves some directories around.
# This is because the GNU tools like to place everyting in "prefix/target",
# and we really want just "prefix" since that is what CMake does.
#

download_dependency(
    binutils
    ${BAREFLANK_BINUTILS_URL}
    ${BAREFLANK_BINUTILS_URL_MD5}
)

list(APPEND BAREFLANK_BINUTILS_CONFIGURE_FLAGS
    # Tell binutils which target we are building for. In general, this step is
    # only needed because this will run on cygwin, and it ensures that we get
    # a linker that outputs ELF.
    --target=${BAREFLANK_TARGET}

    # This tells the compiler where to put the resulting binutils binaries.
    # Note that we will have to modify the results of this as binutils will
    # place the contents in a target folder which we do not want.
    --prefix=${BAREFLANK_PREFIX_DIR}/tmp/

    # This ensures that the linker is compiled with sysroot support. On some
    # systems (like Fedora) this is not the case which is why our own binutils
    # is still needed (that and cygwin)
    --with-sysroot

    # Turn off errors. Oddly, if we do not state this, certain version of
    # binutils will not compile as they have warnings. Just depends on the
    # combination of compilers and the binutils version.
    --disable-werror
)

add_dependency(
    binutils            host
    CONFIGURE_COMMAND   ${BAREFLANK_CACHE_DIR}/binutils/configure ${BAREFLANK_BINUTILS_CONFIGURE_FLAGS}
    BUILD_COMMAND       make -j${BAREFLANK_HOST_NUMBER_CORES}
    INSTALL_COMMAND     make install
)

add_dependency_step(
    binutils    host
    COMMAND     ${CMAKE_COMMAND} -E copy ${BAREFLANK_PREFIX_DIR}/tmp/${BAREFLANK_TARGET}/bin/ld ${BAREFLANK_PREFIX_DIR}/host/bin/ld
    COMMAND     ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_PREFIX_DIR}/tmp/
)
