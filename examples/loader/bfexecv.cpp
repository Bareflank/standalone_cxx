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

#include <vector>
#include <fstream>
#include <filesystem>

#include <bfexec.h>

// -----------------------------------------------------------------------------
// bfexec "funcs"
// -----------------------------------------------------------------------------

#include <cerrno>
#include <cstdlib>
#include <unistd.h>

void *
platform_alloc(size_t size)
{ return aligned_alloc(0x20000, size); }

void
platform_free(void *ptr, size_t size)
{ bfignored(size); return free(ptr); }

status_t
platform_mark_rx(void *addr, size_t size)
{
    if (mprotect(addr, size, PROT_READ|PROT_EXEC) != 0) {
        return BFFAILURE;
    }

    return BFSUCCESS;
}

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

bfexec_funcs_t funcs = {
    .alloc = platform_alloc,
    .free = platform_free,
    .mark_rx = platform_mark_rx,
    .syscall = platform_syscall
};

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

int main(int argc, const char *argv[])
{
    std::vector<char> file;

    if (argc != 2) {
        throw std::runtime_error("wrong number of arguments");
    }

    if (auto strm = std::ifstream(argv[1], std::fstream::binary)) {
        auto size = std::filesystem::file_size(argv[1]);
        file.reserve(size);
        strm.read(file.data(), size);
    }
    else {
        throw std::runtime_error("failed to open input file");
    }

    const char *bfargv[] = {
        argv[1], " Fork: https://github.com/Bareflank/standalone_cxx"
    };

    return bfexecv(file.data(), 2, bfargv, &funcs);
}
