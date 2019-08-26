//
// Copyright (C) 2019 Assured Information Security, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

// TIDY_EXCLUSION=-readability-non-const-parameter
//
// Reason:
//     This file implements C specific functions with defintions that we do
//     not have control over. As a result, this test triggers a false
//     positive
//

// TIDY_EXCLUSION=-cppcoreguidelines-pro*
//
// Reason:
//     Although written in C++, this code needs to implement C specific logic
//     that by its very definition will not adhere to the core guidelines
//     similar to libc which is needed by all C++ implementations.
//

#include <new>
#include <cerrno>

#include <bftypes.h>
#include <bfweak.h>
#include <bfsyscall.h>

//------------------------------------------------------------------------------
// Files
//------------------------------------------------------------------------------

extern "C" WEAK_SYM int
open(const char *file, int oflag, ...)
{
    struct bfsyscall_open_args args = {
        file, oflag, ENOSYS, -1
    };

    bfsyscall(BFSYSCALL_OPEN, &args);

    if (args.error != 0) {
        errno = args.error;
    }

    return args.ret;
}

extern "C" WEAK_SYM int
close(int fd)
{
    struct bfsyscall_close_args args = {
        fd, ENOSYS, -1
    };

    bfsyscall(BFSYSCALL_CLOSE, &args);

    if (args.error != 0) {
        errno = args.error;
    }

    return args.ret;
}

extern "C" WEAK_SYM _READ_WRITE_RETURN_TYPE
write(int fd, const void *buf, size_t nbyte)
{
    struct bfsyscall_write_args args = {
        fd, buf, nbyte, ENOSYS, 0
    };

    bfsyscall(BFSYSCALL_WRITE, &args);

    if (args.error != 0) {
        errno = args.error;
    }

    return args.ret;
}

extern "C" WEAK_SYM _READ_WRITE_RETURN_TYPE
read(int fd, void *buf, size_t nbyte)
{
    struct bfsyscall_read_args args = {
        fd, buf, nbyte, ENOSYS, 0
    };

    bfsyscall(BFSYSCALL_READ, &args);

    if (args.error != 0) {
        errno = args.error;
    }

    return args.ret;
}

extern "C" WEAK_SYM int
fstat(int fd, struct stat *sbuf)
{
    struct bfsyscall_fstat_args args = {
        fd, sbuf, ENOSYS, -1
    };

    bfsyscall(BFSYSCALL_FSTAT, &args);

    if (args.error != 0) {
        errno = args.error;
    }

    return args.ret;
}

extern "C" WEAK_SYM int
lseek(int fd, int offset, int whence)
{
    struct bfsyscall_lseek_args args = {
        fd, offset, whence, ENOSYS, -1
    };

    bfsyscall(BFSYSCALL_LSEEK, &args);

    if (args.error != 0) {
        errno = args.error;
    }

    return args.ret;
}

extern "C" WEAK_SYM int
isatty(int fd)
{
    struct bfsyscall_isatty_args args = {
        fd, ENOSYS, 0
    };

    bfsyscall(BFSYSCALL_ISATTY, &args);

    if (args.error != 0) {
        errno = args.error;
    }

    return args.ret;
}

//------------------------------------------------------------------------------
// Process Info
//------------------------------------------------------------------------------

extern "C" WEAK_SYM int
getpid(void)
{ return 0; }

extern "C" WEAK_SYM int
kill(int _pid, int _sig)
{
    bfignored(_pid);
    bfignored(_sig);

    errno = -ENOSYS;
    return -1;
}

//------------------------------------------------------------------------------
// Exit
//------------------------------------------------------------------------------

extern "C" WEAK_SYM void
_exit(int status)
{
    struct bfsyscall_exit_args args = {
        status
    };

    bfsyscall(BFSYSCALL_EXIT, &args);
    while(1) {}
}

//------------------------------------------------------------------------------
// Memory Management
//------------------------------------------------------------------------------

extern "C" WEAK_SYM WEAK_SYM void *
sbrk(ptrdiff_t incr)
{
    static uint8_t g_heap[BFHEAP_SIZE] = {};
    static uint8_t *g_heap_cursor = g_heap;

    auto cursor = g_heap_cursor;

    if (incr != 0) {
        if (g_heap_cursor + incr >= g_heap + BFHEAP_SIZE) {
            errno = ENOMEM;
            return reinterpret_cast<void *>(-1);
        }

        g_heap_cursor += incr;
    }

    return cursor;
}

extern "C" WEAK_SYM int
posix_memalign(void **memptr, size_t alignment, size_t size)
{
    bfignored(alignment);

    // TODO:
    //
    // Fix this. Once we have our own Libc, we can address this issue with
    // whatever allocation engine we choose to use.
    //

    if (*memptr = new (std::nothrow) char[size]; *memptr != nullptr) {
        return 0;
    }

    return ENOMEM;
}
