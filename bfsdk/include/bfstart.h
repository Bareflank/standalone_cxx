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
 * @file bfstart.h
 */

#ifndef BFSTART_H
#define BFSTART_H

#include "bftypes.h"

#pragma pack(push, 1)

/**
 * @struct _start_args_t
 *
 * Provides information needed when executing _start
 *
 * @var section_info_t::eh_frame_addr (auto filled in)
 *      the address of the eh_frame section in the ELF file
 * @var section_info_t::eh_frame_size (auto filled in)
 *      the size of the eh_frame section in the ELF file
 * @var section_info_t::init_array_addr (auto filled in)
 *      the address of the init section in the ELF file
 * @var section_info_t::init_array_size (auto filled in)
 *      the size of the init section in the ELF file
 * @var section_info_t::fini_array_addr (auto filled in)
 *      the address of the fini section in the ELF file
 * @var section_info_t::fini_array_size (auto filled in)
 *      the size of the fini section in the ELF file
 * @var section_info_t::argc (optional)
 *      main()'s argc
 * @var section_info_t::argv (optional)
 *      main()'s argv
 * @var section_info_t::exec (required)
 *      a pointer to the application
 * @var section_info_t::tls (required)
 *      a pointer to the TLS block the application will use
 * @var section_info_t::stack (required)
 *      a pointer to the stack the application will use
 * @var section_info_t::heap (required)
 *      a pointer to the heap the application will use
 * @var section_info_t::heap_size (required)
 *      the size of the heap the application will use
 * @var section_info_t::thread_id (default to 0)
 *      the ID of the application's thread when started (usually 0)
 * @var section_info_t::alloc (optional)
 *      the alloc function to use when allocating the TLS block, stack or heap
 * @var section_info_t::free (optional)
 *      the free function to use when freeing the TLS block, stack or heap
 * @var section_info_t::syscall (optional)
 *      the syscall function to use when a syscall is made.
 */
struct _start_args_t {
    uint64_t eh_frame_addr;
    uint64_t eh_frame_size;
    uint64_t init_array_addr;
    uint64_t init_array_size;
    uint64_t fini_array_addr;
    uint64_t fini_array_size;
    int32_t argc;
    const char **argv;
    void *exec;
    void *tls;
    void *stack;
    void *heap;
    uint64_t heap_size;
    uint64_t thread_id;
    void *(*alloc)(size_t size);
    void (*free)(void *ptr, size_t size);
    void (*syscall)(uint64_t id, void *args);
};

#ifdef __cplusplus

/**
 * Start Type
 *
 * Defines the function signature for the _start function
 */
using _start_t = status_t (*)(uint64_t, const struct _start_args_t *);

#else

/**
 * Start Type
 *
 * Defines the function signature for the _start function
 */
typedef status_t (*_start_t)(uint64_t, const struct _start_args_t *);

#endif

#pragma pack(pop)

#endif
