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

#include <errno.h>
#include <stdlib.h>

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <tuple>
#include <string>
#include <iostream>

#include <bfexec.h>

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

void *
platform_alloc(size_t size)
{ return aligned_alloc(0x1000, size); }

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
            std::cout << "yo: " << args->fd << '\n';
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
    platform_alloc,
    platform_free,
    platform_mark_rx,
    platform_syscall
};

// -----------------------------------------------------------------------------
// Map File
// -----------------------------------------------------------------------------

std::tuple<char *, size_t, int>
map_file(const std::string &filename)
{
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error("failed to open file: " + filename);
    }

    struct stat s = {};
    if (int ret = fstat(fd, &s); ret == -1) {
        close(fd);
        throw std::runtime_error("failed to fstat file: " + filename);
    }

    auto file = mmap(0, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        close(fd);
        throw std::runtime_error("failed to mmap file: " + filename);
    }

    return {static_cast<char *>(file), s.st_size, fd};
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    auto [file, size, fd] = map_file(argv[1]);

    if (bfexec(file, size, &funcs) != BFSUCCESS) {
        throw std::runtime_error("bfexec returned error code");
    }

    munmap(file, size);
    close(fd);

    return 0;
}
