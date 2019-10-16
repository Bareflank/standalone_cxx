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

include(ExternalProject)

# ------------------------------------------------------------------------------
# include_dependency
# ------------------------------------------------------------------------------

macro(include_dependency NAME)
    include(${CMAKE_CURRENT_LIST_DIR}/cmake/depends/${NAME}.cmake)
endmacro(include_dependency)

# ------------------------------------------------------------------------------
# download_dependency
# ------------------------------------------------------------------------------

# Downloads a dependency from a URL. Dependencies can either be
# a tarball or a zip file. These downloaded files are placed in the BAREFLANK_CACHE_DIR.
# If the provided MD5 hash does not match, the cached download is redownloaded.
#
# @param NAME the name of the dependency
# @param URL The URL for the dependency
# @param URL_MD5 The MD5 of the file being downloaded
#
function(download_dependency NAME URL URL_MD5)
    set(SRC ${BAREFLANK_CACHE_DIR}/${NAME})

    string(REGEX REPLACE "\\.[^.]*$" "" FILENAME ${URL})
    string(REPLACE "${FILENAME}" "" EXT ${URL})
    get_filename_component(LONG_EXT ${URL} EXT)
    if(NOT LONG_EXT MATCHES "(\\.|=)(7z|tar\\.bz2|tar\\.gz|tar\\.xz|tbz2|tgz|txz|zip)$")
        message(FATAL_ERROR "Unsupported file format: ${URL}")
    endif()

    if(LONG_EXT MATCHES ".tar.gz$")
        set(EXT ".tar.gz")
    endif()

    if(LONG_EXT MATCHES ".tar.xz$")
        set(EXT ".tar.xz")
    endif()

    if(LONG_EXT MATCHES ".tar.bz2$")
        set(EXT ".tar.bz2")
    endif()

    set(TMP ${BAREFLANK_CACHE_DIR}/${NAME}_tmp)
    set(TAR ${BAREFLANK_CACHE_DIR}/${NAME}${EXT})

    message(STATUS "    file location: ${TAR}")

    # TODO
    #
    # If a dependency needs to be downloaded, currently, we remove the
    # source directory which forces a recompile. We need to verify that
    # when this happens, all of the targets that rely on this dependency
    # are also recompiled / relinked.
    #

    foreach(ATTEMPT RANGE 1 5 1)
        if(EXISTS "${TAR}")
            message(STATUS "    checking hash: ${URL_MD5}")
            file(MD5 ${TAR} MD5)
            if(NOT "${MD5}" STREQUAL "${URL_MD5}")
                message(STATUS "    ${Red}md5 mismatch: expecting ${URL_MD5}, got ${MD5}${ColorReset}")
                set_property(GLOBAL PROPERTY "FORCE_REBUILD" "ON")
                file(REMOVE_RECURSE ${SRC})
                file(REMOVE_RECURSE ${TMP})
                file(REMOVE_RECURSE ${TAR})
                message(STATUS "    checking hash: ${Yellow}complete, redownload required${ColorReset}")
            else()
                message(STATUS "    checking hash: ${Green}complete${ColorReset}")
                break()
            endif()
        endif()

        if(ATTEMPT GREATER 1)
            message(STATUS "    attempt: ${ATTEMPT}")
        endif()

        message(STATUS "    download file: ${URL} -> ${TAR}")
        file(DOWNLOAD ${URL} ${TAR} STATUS DOWNLOAD_STATUS)
        if(NOT DOWNLOAD_STATUS MATCHES "0;")
            message(STATUS "    ${Red}failed to download ${URL}${ColorReset}")
            file(REMOVE_RECURSE ${TAR})
            continue()
        endif()
        message(STATUS "    download file: ${Green}complete${ColorReset}")
    endforeach()

    if(EXISTS ${TAR})
        file(MD5 ${TAR} MD5)
        if(NOT "${MD5}" STREQUAL "${URL_MD5}")
            message(FATAL_ERROR "Failed to download ${URL} with md5 hash of ${URL_MD5}")
        endif()
    else()
        message(FATAL_ERROR "Failed to download ${URL} with md5 hash of ${URL_MD5}")
    endif()

    if(NOT EXISTS "${SRC}")
        file(REMOVE_RECURSE ${TMP})
        file(REMOVE_RECURSE ${SRC})
        file(MAKE_DIRECTORY ${TMP})

        execute_process(
            COMMAND ${CMAKE_COMMAND} -E tar xfz ${TAR}
            WORKING_DIRECTORY ${TMP}
        )

        file(GLOB CONTENTS "${TMP}/*")

        list(LENGTH CONTENTS LEN)
        if(NOT LEN EQUAL 1 OR NOT IS_DIRECTORY ${CONTENTS})
            message(FATAL_ERROR "Invalid tarball: ${URL}")
        endif()

        get_filename_component(CONTENTS ${CONTENTS} ABSOLUTE)
        execute_process(
            COMMAND ${CMAKE_COMMAND} -E rename ${CONTENTS} ${SRC}
        )

        file(REMOVE_RECURSE ${TMP})
    endif()
endfunction(download_dependency)

# ------------------------------------------------------------------------------
# add_dependency
# ------------------------------------------------------------------------------

# Uses ExternalProject_Add to add the dependency to the build. All of the
# optional arguments are passed directly to ExternalProject_Add, so most of
# ExternalProject_Add's options are supported by this function.
#
# @param NAME the name of the dependency
# @param PREFIX the prefix to install the dependency
#
function(add_dependency NAME PREFIX)
    if(EXISTS "${BAREFLANK_CACHE_DIR}/${NAME}/CMakeLists.txt")
        if(PREFIX MATCHES "target")
            list(APPEND ARGN
                CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}
            )
        else()
            list(APPEND ARGN
                CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${BAREFLANK_PREFIX_DIR}/host
            )
        endif()

        if(PREFIX MATCHES "target")
            list(APPEND ARGN
                CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${BAREFLANK_TOOLCHAIN_FILE}
            )
        else()
            list(APPEND ARGN
                CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
                CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
                CMAKE_ARGS -DCMAKE_BUILD_TYPE=${BAREFLANK_HOST_BUILD_TYPE}
            )

            if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
                list(APPEND ARGN
                    CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
                )
            endif()
        endif()
    elseif(NOT CMAKE_VERBOSE_MAKEFILE)
        list(APPEND ARGN
            LOG_CONFIGURE 1
            LOG_BUILD 1
            LOG_INSTALL 1
        )
    endif()

    ExternalProject_Add(
        ${NAME}_${PREFIX}
        ${ARGN}
        PREFIX              ${BAREFLANK_DEPENDS_DIR}/${NAME}_${PREFIX}
        STAMP_DIR           ${BAREFLANK_DEPENDS_DIR}/${NAME}_${PREFIX}/stamp
        TMP_DIR             ${BAREFLANK_DEPENDS_DIR}/${NAME}_${PREFIX}/tmp
        BINARY_DIR          ${BAREFLANK_DEPENDS_DIR}/${NAME}_${PREFIX}/build
        LOG_DIR             ${BAREFLANK_DEPENDS_DIR}/${NAME}_${PREFIX}/logs
        SOURCE_DIR          ${BAREFLANK_CACHE_DIR}/${NAME}
        DEPENDS             ${DEPENDS}
    )

    ExternalProject_Add_Step(
        ${NAME}_${PREFIX}
        ${NAME}_${PREFIX}_cleanup
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_DEPENDS_DIR}/${NAME}_${PREFIX}/src
        DEPENDEES configure
    )
endfunction(add_dependency)

# Uses ExternalProject_Add_Step to add an additional step to external project
# add after "install" is executed by ExternalProject_Add. Only one additional
# step is supported. Like add_dependency, add_dependency_step passes all
# optional parameters to ExternalProject_Add_Step, so most options are
# supported.
#
# @param NAME the name of the dependency
# @param PREFIX the prefix to install the dependency
#
function(add_dependency_step NAME PREFIX)
    ExternalProject_Add_Step(
        ${NAME}_${PREFIX}
        step_${NAME}_${PREFIX}
        ${ARGN}
        DEPENDEES install
    )
endfunction(add_dependency_step)

# ------------------------------------------------------------------------------
# add_subproject
# ------------------------------------------------------------------------------

# Uses ExternalProject_Add to add a subproject to the build. All of the
# optional arguments are passed directly to ExternalProject_Add, so most of
# ExternalProject_Add's options are supported by this function.
#
# @param NAME the name of the subproject
# @param PREFIX the prefix to install the subproject
#
function(add_subproject NAME PREFIX)
    if(PREFIX MATCHES "target")
        list(APPEND ARGN
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}
        )
    else()
        list(APPEND ARGN
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${BAREFLANK_PREFIX_DIR}/host
        )
    endif()

    if(PREFIX MATCHES "target")
        if(NOT NAME MATCHES "uefi")
            list(APPEND ARGN
                CMAKE_ARGS -DCMAKE_TOOLCHAIN_FILE=${BAREFLANK_TOOLCHAIN_FILE}
            )
        endif()
    else()
        list(APPEND ARGN
            CMAKE_ARGS -DCMAKE_INSTALL_MESSAGE=${CMAKE_INSTALL_MESSAGE}
            CMAKE_ARGS -DCMAKE_VERBOSE_MAKEFILE=${CMAKE_VERBOSE_MAKEFILE}
            CMAKE_ARGS -DCMAKE_BUILD_TYPE=${BAREFLANK_HOST_BUILD_TYPE}
        )

        if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
            list(APPEND ARGN
                CMAKE_ARGS -DCMAKE_TARGET_MESSAGES=${CMAKE_TARGET_MESSAGES}
            )
        endif()
    endif()

    ExternalProject_Add(
        ${NAME}_${PREFIX}
        ${ARGN}
        PREFIX              ${BAREFLANK_SUBPROJECT_DIR}/${NAME}_${PREFIX}
        STAMP_DIR           ${BAREFLANK_SUBPROJECT_DIR}/${NAME}_${PREFIX}/stamp
        TMP_DIR             ${BAREFLANK_SUBPROJECT_DIR}/${NAME}_${PREFIX}/tmp
        BINARY_DIR          ${BAREFLANK_SUBPROJECT_DIR}/${NAME}_${PREFIX}/build
        LOG_DIR             ${BAREFLANK_SUBPROJECT_DIR}/${NAME}_${PREFIX}/logs
        UPDATE_COMMAND      cmake -E echo -- Checking for changes
        DEPENDS             ${DEPENDS}
    )

    ExternalProject_Add_Step(
        ${NAME}_${PREFIX}
        ${NAME}_${PREFIX}_cleanup
        COMMAND ${CMAKE_COMMAND} -E remove_directory ${BAREFLANK_SUBPROJECT_DIR}/${NAME}_${PREFIX}/src
        DEPENDEES configure
    )
endfunction(add_subproject)

# ------------------------------------------------------------------------------
# setup_interfaces
# ------------------------------------------------------------------------------

# Creates the public libraries interfaces so that other projects can leverage
# the standalone c++ libraries without any issues using CMake. All of the
# compiler options, flags and libraries are defined here so that users of our
# libraries do not need to understand how to compile
#
function(setup_interfaces)
    add_library(standalone_cxx INTERFACE)
    add_library(standalone_cxx_sdk INTERFACE)

    target_link_libraries(standalone_cxx INTERFACE
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libc++.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libc++abi.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libbfunwind.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libc.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libm.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libbfruntime.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libc++.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libc++abi.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libbfunwind.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libc.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libm.a
        ${BAREFLANK_PREFIX_DIR}/${BAREFLANK_TARGET}/lib/libbfruntime.a
    )

    target_link_directories(standalone_cxx INTERFACE
        ${BAREFLANK_PREFIX_DIR}/host/lib/
    )

    target_link_directories(standalone_cxx_sdk INTERFACE
        ${BAREFLANK_PREFIX_DIR}/host/lib/
    )

    target_include_directories(standalone_cxx_sdk INTERFACE
        ${BAREFLANK_PREFIX_DIR}/host/include/
        ${BAREFLANK_PREFIX_DIR}/host/include/bfsdk
        ${BAREFLANK_PREFIX_DIR}/host/include/bfelf_loader
    )

    target_compile_definitions(standalone_cxx_sdk INTERFACE
        BFHEAP_SIZE=${BAREFLANK_HEAP_SIZE}
        BFSTACK_SIZE=${BAREFLANK_STACK_SIZE}
    )

    target_compile_options(standalone_cxx_sdk INTERFACE
       ${BAREFLANK_HOST_CXX_FLAGS}
    )

    export(TARGETS standalone_cxx FILE standalone_cxxConfig.cmake APPEND)
    export(PACKAGE standalone_cxx)

    export(TARGETS standalone_cxx_sdk FILE standalone_cxx_sdkConfig.cmake APPEND)
    export(PACKAGE standalone_cxx_sdk)
endfunction(setup_interfaces)

# ------------------------------------------------------------------------------
# generate_toolchain
# ------------------------------------------------------------------------------

function(append_if_exists TOOLCHAIN_OUTPUT VAR)
    if(${VAR})
        file(APPEND ${TOOLCHAIN_OUTPUT} "set(${VAR} \"${${VAR}} \")\n")
    endif()
endfunction(append_if_exists)


# Generates a toolchain file based on an input toolchain file that contains
# a bunch of Bareflank specific definitions that a project might need. This
# ensures all of the settings that were used to create the standalone C++
# libraries are also applied to anything that uses the libraries, something
# that a package cannot currently support from a toolchain.
#
# @param TOOLCHAIN_INPUT the input toolchain
# @param TOOLCHAIN_OUTPUT the output toolchain
#
function(generate_toolchain TOOLCHAIN_INPUT TOOLCHAIN_OUTPUT)
    file(REMOVE ${TOOLCHAIN_OUTPUT})
    file(APPEND ${TOOLCHAIN_OUTPUT} "# --- Auto Generated ---\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(CMAKE_INSTALL_MESSAGE ${CMAKE_INSTALL_MESSAGE})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(CMAKE_VERBOSE_MAKEFILE ${CMAKE_VERBOSE_MAKEFILE})\n")

    if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
        file(APPEND ${TOOLCHAIN_OUTPUT} "set(CMAKE_TARGET_MESSAGES ${CMAKE_TARGET_MESSAGES})\n")
    endif()

    append_if_exists(${TOOLCHAIN_OUTPUT} BAREFLANK_TARGET_C_FLAGS)
    append_if_exists(${TOOLCHAIN_OUTPUT} BAREFLANK_TARGET_CXX_FLAGS)
    append_if_exists(${TOOLCHAIN_OUTPUT} BAREFLANK_TARGET_LINK_FLAGS)

    if(BAREFLANK_TARGET)
        file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_TARGET ${BAREFLANK_TARGET})\n")
    endif()

    file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_CACHE_DIR ${BAREFLANK_CACHE_DIR})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_PREFIX_DIR ${BAREFLANK_PREFIX_DIR})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_DEPENDS_DIR ${BAREFLANK_DEPENDS_DIR})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_TARGET_BUILD_TYPE ${BAREFLANK_TARGET_BUILD_TYPE})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_CLANG_BIN ${BAREFLANK_CLANG_BIN})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_LD_BIN ${BAREFLANK_LD_BIN})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_HEAP_SIZE ${BAREFLANK_HEAP_SIZE})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "set(BAREFLANK_STACK_SIZE ${BAREFLANK_STACK_SIZE})\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "# --- Auto Generated ---\n")
    file(APPEND ${TOOLCHAIN_OUTPUT} "\n")

    file(READ ${TOOLCHAIN_INPUT} INPUT_CONTENTS)
    file(APPEND ${TOOLCHAIN_OUTPUT} "${INPUT_CONTENTS}")
endfunction(generate_toolchain)
