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

#ifndef BFHEAP_ALLOC_SIZE
#define BFHEAP_ALLOC_SIZE BFHEAP_SIZE
#endif

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
 * Alloc TLS
 *
 * @param a function pointer to an alloc function
 * @return a pointer to a newly allocated TLS block
 */
static inline void *
alloc_tls(void *(*alloc)(size_t size))
{
    size_t i;
    void *ptr = alloc(BFTLS_ALLOC_SIZE);

    if (ptr == nullptr) {
        BFALERT("alloc_tls failed to allocate the TLS block\n");
        return nullptr;
    }

    for (i = 0; i < BFTLS_ALLOC_SIZE; i++) {
        BFSCAST(char*, ptr)[i] = 0;
    }

    return ptr;
}

/**
 * Alloc Stack
 *
 * @param a function pointer to an alloc function
 * @return a pointer to a newly allocated stack
 */
static inline void *
alloc_stack(void *(*alloc)(size_t size))
{
    void *ptr = alloc(BFSTACK_ALLOC_SIZE);

    if (ptr == nullptr) {
        BFALERT("alloc_stack failed to allocate the stack\n");
        return nullptr;
    }

    return ptr;
}

/**
 * Alloc Heap
 *
 * @param a function pointer to an alloc function
 * @return a pointer to a newly allocated heap
 */
static inline void *
alloc_heap(void *(*alloc)(size_t size))
{
    void *ptr = alloc(BFHEAP_ALLOC_SIZE);

    if (ptr == nullptr) {
        BFALERT("alloc_heap failed to allocate the heap\n");
        return nullptr;
    }

    return ptr;
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
    status_t ret;
    uint64_t sp = 0;

#ifdef BFINCLUDE_ALLOCATIONS
    static char s_tls[BFTLS_ALLOC_SIZE] = {0};
    static char s_stack[BFSTACK_ALLOC_SIZE];
    static char s_heap[BFHEAP_ALLOC_SIZE];

    void *tls = s_tls;
    void *stack = s_stack;
    void *heap = s_heap;

    _start_args->tls = s_tls;
    _start_args->stack = s_stack;
    _start_args->heap = s_heap;
#else
    void *tls = _start_args->tls;
    void *stack = _start_args->stack;
    void *heap = _start_args->heap;
#endif

    if (ef == nullptr) {
        BFALERT("bfexec failed: invalid ELF file\n");
        return BFFAILURE;
    }

    if (_start_args == nullptr) {
        BFALERT("bfexec failed: invalid _start_args\n");
        return BFFAILURE;
    }

    if (ef->relocated == 0) {
        if (_start_args->exec == nullptr) {
            BFALERT("bfexec failed: exec must be set if ELF is not relocated\n");
            return BFFAILURE;
        }

        ef->exec = BFSCAST(uint8_t *, _start_args->exec);
        if (bfelf_file_relocate(ef, 0) != BFSUCCESS) {
            BFALERT("bfexec failed: bfelf_file_relocate failed\n");
            return BFFAILURE;
        }
    }

    if (tls == nullptr || stack == nullptr || heap == nullptr) {
        if (_start_args->alloc == nullptr) {
            BFALERT("bfexec failed: if tls, stack or heap is not set, alloc must be set\n");
            return BFFAILURE;
        }
    }

    if (_start_args->tls == nullptr) {
        _start_args->tls = alloc_tls(_start_args->alloc);
        if (_start_args->tls == nullptr) {
            BFALERT("bfexec failed: failed to allocate the tls block\n");
            goto release;
        }
    }

    if (_start_args->stack == nullptr) {
        _start_args->stack = alloc_stack(_start_args->alloc);
        if (_start_args->stack == nullptr) {
            BFALERT("bfexec failed: failed to allocate the stack\n");
            goto release;
        }
    }

    if (_start_args->heap == nullptr) {
        _start_args->heap = alloc_heap(_start_args->alloc);
        if (_start_args->heap == nullptr) {
            BFALERT("bfexec failed: failed to allocate the heap\n");
            goto release;
        }
    }

    if (_start_args->heap_size == 0) {
        _start_args->heap_size = BFHEAP_ALLOC_SIZE;
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

    ret = ((_start_t)ef->entry)(sp, _start_args);

    if (validate_canaries(_start_args->stack) != BFSUCCESS) {
        BFALERT("stack corruption detected!!!\n");
        return BFFAILURE;
    }

release:

    if (_start_args->free != nullptr && tls == nullptr) {
        _start_args->free(_start_args->tls, BFTLS_ALLOC_SIZE);
    }

    if (_start_args->free != nullptr && stack == nullptr) {
        _start_args->free(_start_args->stack, BFSTACK_ALLOC_SIZE);
    }

    if (_start_args->free != nullptr && heap == nullptr) {
        _start_args->free(_start_args->heap, BFHEAP_ALLOC_SIZE);
    }

    return ret;
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
 * @param argc the number of arguments to pass to ELF file on start
 * @param argv the arguments to pass to the ELF file on start
 * @param funcs helper functions needed by bfexec and friends
 * @return BFSUCCESS on success, BFFAILURE otherwise
 */
static inline status_t
bfexecv(
    void *file,
    int argc,
    const char **argv,
    struct bfexec_funcs_t *funcs)
{
    status_t ret;

    void *exec;
    struct bfelf_file_t ef;
    struct _start_args_t _start_args = {0};

    if (file == nullptr) {
        BFALERT("bfexec failed: invalid ELF file\n");
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

    if (bfelf_file_init(file, &ef) != BFSUCCESS) {
        BFALERT("bfexec failed: failed to init ELF file\n");
        return BFFAILURE;
    }

    exec = funcs->alloc(ef.size);
    if (exec == nullptr) {
        BFALERT("bfexec failed: failed to allocate memory for exec\n");
        return BFFAILURE;
    }

    if (bfelf_file_load(&ef, exec, funcs->mark_rx) != BFSUCCESS) {
        BFALERT("bfexec failed: failed to load ELF file\n");
        goto release;
    }

    if (bfelf_file_relocate(&ef, 0) != BFSUCCESS) {
        BFALERT("bfexec failed: failed to relocate ELF file\n");
        goto release;
    }

    _start_args.argc = argc;
    _start_args.argv = argv;
    _start_args.alloc = funcs->alloc;
    _start_args.free = funcs->free;
    _start_args.syscall = funcs->syscall;

    ret = bfexecs(&ef, &_start_args);

release:

    if (funcs->free != nullptr) {
        funcs->free(exec, ef.size);
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
    struct bfexec_funcs_t *funcs)
{ return bfexecv(file, 0, nullptr, funcs); }

#endif
