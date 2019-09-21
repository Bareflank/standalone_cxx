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

#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#define BFINCLUDE_ALLOCATIONS

#include <bfexec.h>
#include <stdexcept>

// -----------------------------------------------------------------------------
// Binary Includes
// -----------------------------------------------------------------------------

extern void *file;
extern size_t file_size;
extern struct bfelf_file_t *ef;

// -----------------------------------------------------------------------------
// Helper Functions
// -----------------------------------------------------------------------------

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

int main(int argc, char *argv[])
{
    // The following are the arguments that we pass to bfexec. We defined the
    // BFINCLUDE_ALLOCATIONS macro, which tells bfexec to create the TLS block,
    // stack and the heap for us. You could also allocate these yourself using
    // dynamic allocation.
    //
    struct _start_args_t args = {
        .tls = g_tls,
        .stack = g_stack,
        .heap = g_heap,
        .syscall_func = platform_syscall
    };

    // The ELF file that we will load is compiled directly into this loader
    // using the incbin command in the assembly function. This will get pulled
    // into the .data section which is read/write. From there, we need to mark
    // this section as read/write/execute so that we can execute the C++.
    //
    // Note:
    //
    // If you want better control of the permissions (i.e., to peroperly mark
    // each section as read/write and read/execute), in the compile application
    // that executes before this to convert the ELF file to an ELF binary,
    // provide the ELF loader with a mark_rx function and record the locations
    // in memory that must be marked as RX. Hand this information to the this
    // code (similar to how we hand the ef structure), and then mark each
    // section as read/execute, with everything else marked as read/write by
    // default.
    //
    if (mprotect(file, file_size, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) {
        return BFFAILURE;
    }

    // We have to set the ef->exec to a nullptr as it has the exec location
    // from the loader. By setting it to 0, the ELF loader will automatically
    // use exec to the "virt" parameter that is provided below.
    //
    ef->exec = nullptr;
    if (bfelf_file_relocate(ef, reinterpret_cast<uint64_t>(file)) != BFSUCCESS) {
        throw std::runtime_error("failed to load the payload ELF file");
    }

    // Finally, we just call the bfexecs function, which will execute the C++
    // code for us from the loader. Note that there are no malloc()s that occur
    // in this version of the loader, reducing the memory requirements and
    // simplifying things.
    //
    if (bfexecs(ef, &args) != BFSUCCESS) {
        throw std::runtime_error("bfexec returned error code");
    }

    return 0;
}
