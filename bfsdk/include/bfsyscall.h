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
 * @file bfsyscall.h
 */

#ifndef BFSYSCALL_H
#define BFSYSCALL_H

#include "bftypes.h"

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Syscall
 *
 * Executes a syscall by calling an external syscall function that the loader
 * provides. Any functionality that the C++ application cannot execute on its
 * own should be routed via this function to the loader to handle.
 *
 * @param id the syscall id that is being called.
 * @param args the arguments for the syscall.
 * @param syscall_func a pointer to the syscall function that the loader
 *     uses. This is usually g_syscall_func
 */
void bfsyscall(uint64_t id, void *args);

#ifdef __cplusplus

/**
 * Syscall Function Type
 *
 * Defines the function signature for the syscall function
 */
using syscall_func_t = void (*)(uint64_t, void *);

#else

/**
 * Syscall Function Type
 *
 * Defines the function signature for the syscall function
 */
typedef void (*syscall_func_t)(uint64_t, void *);

#endif

/**
 * @cond
 */

#define BFSYSCALL_OPEN 0xBFCA110000000001
struct bfsyscall_open_args
{
    /** IN */
    const char *file;
    int oflag;

    /** OUT */
    int32_t error;
    int ret;
};

#define BFSYSCALL_CLOSE 0xBFCA110000000002
struct bfsyscall_close_args
{
    /** IN */
    int fd;

    /** OUT */
    int32_t error;
    int ret;
};

#define BFSYSCALL_WRITE 0xBFCA110000000003
struct bfsyscall_write_args
{
    /** IN */
    int fd;
    const void *buf;
    size_t nbyte;

    /** OUT */
    int32_t error;
    size_t ret;
};

#define BFSYSCALL_READ 0xBFCA110000000004
struct bfsyscall_read_args
{
    /** IN */
    int fd;
    const void *buf;
    size_t nbyte;

    /** OUT */
    int32_t error;
    size_t ret;
};

#define BFSYSCALL_FSTAT 0xBFCA110000000005
struct bfsyscall_fstat_args
{
    /** IN */
    int fd;
    void *sbuf;

    /** OUT */
    int32_t error;
    int ret;
};

#define BFSYSCALL_LSEEK 0xBFCA110000000006
struct bfsyscall_lseek_args
{
    /** IN */
    int fd;
    long int offset;
    int whence;

    /** OUT */
    int32_t error;
    int ret;
};

#define BFSYSCALL_ISATTY 0xBFCA110000000007
struct bfsyscall_isatty_args
{
    /** IN */
    int fd;

    /** OUT */
    int32_t error;
    int ret;
};

/**
 * @endcond
 */

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
