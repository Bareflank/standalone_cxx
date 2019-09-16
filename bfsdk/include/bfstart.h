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
#include "bfsyscall.h"

#pragma pack(push, 1)

/**
 * @struct _start_args_t
 *
 * Provides information needed when executing _start
 *
 * @var section_info_t::eh_frame_addr
 *      the address of the eh_frame section in the ELF file
 * @var section_info_t::eh_frame_size
 *      the size of the eh_frame section in the ELF file
 * @var section_info_t::init_array_addr
 *      the address of the init section in the ELF file
 * @var section_info_t::init_array_size
 *      the size of the init section in the ELF file
 * @var section_info_t::fini_array_addr
 *      the address of the fini section in the ELF file
 * @var section_info_t::fini_array_size
 *      the size of the fini section in the ELF file
 * @var section_info_t::argc (only valid when request == 0)
 *      main()'s argc
 * @var section_info_t::argv (only valid when request == 0)
 *      main()'s argv
 * @var section_info_t::exec
 *      a pointer to the executable memory for the application itself.
 * @var section_info_t::stack
 *      a pointer to the stack the application will use
 * @var section_info_t::tls
 *      a pointer to the TLS block the application will use
 * @var section_info_t::thread_id
 *      the ID of the application's thread when started (usually 0)
 * @var section_info_t::syscall_func
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
    char **argv;
    void *exec;
    void *stack;
    void *tls;
    uint64_t thread_id;
    syscall_func_t syscall_func;
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
