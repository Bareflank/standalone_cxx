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

#include <sys/mman.h>
#include <sys/types.h>

#define BFINCLUDE_ALLOCATIONS
#define BFHEAP_ALLOC_SIZE (1 << 13)
#include <bfexec.h>

// -----------------------------------------------------------------------------
// Binary Includes
// -----------------------------------------------------------------------------

extern void *file;
extern size_t file_size;
extern struct bfelf_file_t *ef;

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

#include <cerrno>
#include <cstdlib>
#include <unistd.h>

void
platform_syscall_write(bfsyscall_write_args *args)
{
    switch(args->fd) {
        case STDOUT_FILENO:
        case STDERR_FILENO:
            errno = 0;
            args->ret = write(args->fd, args->buf, args->nbyte);
            args->error = errno;
            return;

        default:
            return;
    }
}

void
platform_syscall(uint64_t id, void *args)
{
    switch(id) {
        case BFSYSCALL_WRITE:
            return platform_syscall_write(
                static_cast<bfsyscall_write_args *>(args));

        default:
            return;
    }
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

int main(int argc, const char *argv[])
{
    struct _start_args_t args = {
        .exec = file,
        .syscall = platform_syscall
    };

    if (mprotect(file, file_size, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) {
        return BFFAILURE;
    }

    return bfexecs(ef, &args);
}
