/*
 * Copyright (C) 2019 Assured Information Security, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file bfexecute.h
 */

#ifndef BFEXECUTE_H
#define BFEXECUTE_H

#include "bfstart.h"
#include "bfsyscall.h"
#include <bfelf_loader.h>
#include "bfthreadcontext.h"

/**
 * Platform Functions
 *
 * @var bfexec_funcs_t::alloc (required)
 *     a pointer to an the alloc function used by bfexec
 * @var bfexec_funcs_t::free (optional)
 *     a pointer to an the free function used by bfexec
 * @var bfexec_funcs_t::mark_rx (optional)
 *     a pointer to an the mark_rx function used by bfexec
 * @var bfexec_funcs_t::syscall (optional)
 *     a pointer to an the syscall function used by bfexec
 */
struct bfexec_funcs_t
{
    void *(*alloc)(size_t size);
    void (*free)(void *ptr, size_t size);
    status_t (*mark_rx)(void *ptr, size_t size);
    void (*syscall)(uint64_t id, void *args);
};

/**
 * Bareflank Execute
 *
 * The "bfexec" functions are similar to the "exec" functions. Both load a
 * program into the current process space and then execute it. There are some
 * key differences however:
 * - Unlike exec, bfexec doesn't have any OS specific dependencies. This allows
 *   it to work on any OS, or even on systems without an OS. As a result, it
 *   takes a buffer to an application and not a file path, since loading a file
 *   is OS/system specific.
 * - Since there are no OS specific dependencies, you must provide some helper
 *   functions that are needed (specifically with memory management and how to
 *   handle system calls).
 *
 * This version of the bfexec function takes an ELF file and the start
 * arguments and will then execute the application. This function will fill in
 * the ELF start args for you, but you do need to fill out the rest of the
 * arguments as needed. In general, unless you know what you are doing, do
 * not use this function and instead use the others.
 *
 * @param ef the ELF file to execute.
 * @param _start_args the start arguments to provide the _start function
 * @return BFSUCCESS on success, BFFAILURE otherwise
 */
static inline status_t
bfexecs(struct bfelf_file_t *ef, struct _start_args_t *_start_args)
{
    uint64_t sp = 0;

    if (ef == NULL) {
        BFALERT("bfexec failed: invalid ELF file\n");
        return BFFAILURE;
    }

    if (_start_args == NULL) {
        BFALERT("bfexec failed: invalid _start_args\n");
        return BFFAILURE;
    }

    if (_start_args->stack == NULL) {
        BFALERT("bfexec failed: invalid _start_args->stack\n");
        return BFFAILURE;
    }

    if (_start_args->tls == NULL) {
        BFALERT("bfexec failed: invalid _start_args->tls\n");
        return BFFAILURE;
    }

    _start_args->eh_frame_addr = ef->eh_frame_addr;
    _start_args->eh_frame_size = ef->eh_frame_size;
    _start_args->init_array_addr = ef->init_array_addr;
    _start_args->init_array_size = ef->init_array_size;
    _start_args->fini_array_addr = ef->fini_array_addr;
    _start_args->fini_array_size = ef->fini_array_size;

    sp = setup_stack(
        _start_args->stack, _start_args->thread_id, _start_args->tls
    );

    if (((_start_t)ef->entry)(sp, _start_args) != 0) {
        BFALERT("_start exited with non-zero exit status\n");
        return BFFAILURE;
    }

    if (validate_canaries(_start_args->stack) != BFSUCCESS) {
        BFALERT("stack corruption detected!!!\n");
        return BFFAILURE;
    }

    return BFSUCCESS;
}

/**
 * Bareflank Execute (With Argc/Argv)
 *
 * The "bfexec" functions are similar to the "exec" functions. Both load a
 * program into the current process space and then execute it. There are some
 * key differences however:
 * - Unlike exec, bfexec doesn't have any OS specific dependencies. This allows
 *   it to work on any OS, or even on systems without an OS. As a result, it
 *   takes a buffer to an application and not a file path, since loading a file
 *   is OS/system specific.
 * - Since there are no OS specific dependencies, you must provide some helper
 *   functions that are needed (specifically with memory management and how to
 *   handle system calls).
 *
 * This version of the bfexec function takes a pointer to the file to load,
 * the files size, and a custom argv/argc that you can pass to the application
 * as needed. This function also needs a set of function pointers for helper
 * functions that are needed for the C++ application to work. The only
 * functions that are required are the alloc and free functions. If no syscall
 * function is provided, system calls will not work (things like console
 * output will not work), and if the mark_rx function is not provided, it is
 * possible the application will not start if memory is not configured with
 * read/write/execute permissions.
 *
 * @param file a pointer to the ELF file to execute
 * @param size the size of the ELF file
 * @param argc the number of arguments to pass to ELF file on start
 * @param argv the arguments to pass to the ELF file on start
 * @param funcs helper functions needed by bfexec and friends
 * @return BFSUCCESS on success, BFFAILURE otherwise
 */
static inline status_t
bfexecv(
    void *file,
    size_t size,
    int argc,
    char **argv,
    struct bfexec_funcs_t *funcs)
{
    size_t i;
    status_t ret;
    struct bfelf_file_t ef;
    struct _start_args_t _start_args = {0};

    if (file == nullptr) {
        BFALERT("bfexec failed: invalid ELF file\n");
        return BFFAILURE;
    }

    if (size == 0) {
        BFALERT("bfexec failed: invalid ELF file size\n");
        return BFFAILURE;
    }

    if (funcs == nullptr) {
        BFALERT("bfexec failed: invalid funcs pointer\n");
        return BFFAILURE;
    }

    if (funcs->alloc == nullptr) {
        BFALERT("bfexec failed: invalid funcs->alloc pointer\n");
        return BFFAILURE;
    }

    ret = bfelf_file_init(file, size, &ef);
    if (ret != BFSUCCESS) {
        BFALERT("bfexec failed: failed to init ELF file\n");
        return BFFAILURE;
    }

    _start_args.exec = bfelf_file_alloc(&ef, funcs->alloc);
    if (_start_args.exec == nullptr) {
        BFALERT("bfexec failed: failed to allocate memory for exec\n");
        return BFFAILURE;
    }

    ret = bfelf_file_load(_start_args.exec, 0, &ef, funcs->mark_rx);
    if (ret != BFSUCCESS) {
        BFALERT("bfexec failed: failed to load ELF file\n");
        goto release;
    }

    _start_args.argc = argc;
    _start_args.argv = argv;
    _start_args.syscall_func = funcs->syscall;

    _start_args.stack = funcs->alloc(__stack_size());
    if (_start_args.stack == nullptr) {
        BFALERT("bfexec failed: failed to allocate stack\n");
        goto release;
    }

    _start_args.tls = funcs->alloc(BFTLS_SIZE);
    if (_start_args.tls == nullptr) {
        BFALERT("bfexec failed: failed to allocate stack\n");
        goto release;
    }

    for (i = 0; i < BFTLS_SIZE; i++) {
        BFSCAST(char*, _start_args.tls)[i] = 0;
    }

    ret = bfexecs(&ef, &_start_args);

release:

    if (funcs->free != nullptr) {
        funcs->free(_start_args.exec, ef.size);
        funcs->free(_start_args.stack, __stack_size());
        funcs->free(_start_args.tls, BFTLS_SIZE);
    }

    return ret;
}

/**
 * Bareflank Execute
 *
 * The "bfexec" functions are similar to the "exec" functions. Both load a
 * program into the current process space and then execute it. There are some
 * key differences however:
 * - Unlike exec, bfexec doesn't have any OS specific dependencies. This allows
 *   it to work on any OS, or even on systems without an OS. As a result, it
 *   takes a buffer to an application and not a file path, since loading a file
 *   is OS/system specific.
 * - Since there are no OS specific dependencies, you must provide some helper
 *   functions that are needed (specifically with memory management and how to
 *   handle system calls).
 *
 * This version of the bfexec function takes a pointer to the file to load,
 * and the files size. This function also needs a set of function pointers for
 * helper functions that are needed for the C++ application to work. The only
 * functions that are required are the alloc and free functions. If no syscall
 * function is provided, system calls will not work (things like console
 * output will not work), and if the mark_rx function is not provided, it is
 * possible the application will not start if memory is not configured with
 * read/write/execute permissions.
 *
 * @param file a pointer to the ELF file to execute
 * @param size the size of the ELF file
 * @param funcs helper functions needed by bfexec and friends
 * @return BFSUCCESS on success, BFFAILURE otherwise
 */
static inline status_t
bfexec(
    void *file,
    size_t size,
    struct bfexec_funcs_t *funcs)
{ return bfexecv(file, size, 0, nullptr, funcs); }

#endif
