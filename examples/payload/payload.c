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

/* -------------------------------------------------------------------------- */
/* Functions                                                                  */
/* -------------------------------------------------------------------------- */

#include <stddef.h>

int (*external_open)(const char *, int, ...) = (void *)0xDEADBEEF00000001;
size_t (*external_filesize)(int) = (void *)0xDEADBEEF00000002;
char *(*external_filemmap)(int, size_t) = (void *)0xDEADBEEF00000003;
void (*external_exit)(int) = (void *)0xDEADBEEF00000004;
void *(*external_malloc)(size_t) = (void *)0xDEADBEEF00000005;
size_t (*external_write)(int, const void *, size_t) = (void *)0xDEADBEEF00000006;
int (*external_mprotect)(void *, size_t, int) = (void *)0xDEADBEEF00000007;
int (*external_fprintf)(void*, const char *, ... ) = (void *)0xDEADBEEF00000008;
void *external_stderr = (void *)0xDEADBEEF00000009;

/* -------------------------------------------------------------------------- */
/* Bareflank Exec                                                             */
/* -------------------------------------------------------------------------- */

#define BFALERT(...) external_fprintf(external_stderr, "[BAREFLANK ALERT]: " __VA_ARGS__)
#include <bfexec.h>

/* -------------------------------------------------------------------------- */
/* Return Address                                                             */
/* -------------------------------------------------------------------------- */

#define STACK __attribute__((section(".custom_stack")))
#define STACK_SIGNATURE ((void *))

STACK void *stack_pad[20] = {0};
STACK void *stack_rbp = 0;
STACK void *stack_ret = (void *)0xDEADBEEF00000000;

/* ---------------------------------------------------------------------------*/
/* Helpers Functions                                                          */
/* ---------------------------------------------------------------------------*/

void *
platform_alloc(size_t size)
{ return (void *)((uint64_t)external_malloc(size + 0x1000) & 0xFFFFFFFFFFFFF000ULL); }

void
platform_free(void *ptr, size_t size)
{ bfignored(ptr); bfignored(size); }

status_t
platform_mark_rx(void *addr, size_t size)
{
    if (external_mprotect(addr, size, 5) != 0) {
        return BFFAILURE;
    }

    return BFSUCCESS;
}

void
platform_syscall_write(struct bfsyscall_write_args *args)
{
    switch(args->fd) {
        case 1:
        case 2:
            args->ret = external_write(args->fd, args->buf, args->nbyte);
            args->error = 0;
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
            return platform_syscall_write(args);

        default:
            return;
    }
}

struct bfexec_funcs_t funcs = {
    platform_alloc,
    platform_free,
    platform_mark_rx,
    platform_syscall
};

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

void start_c()
{
    char *file;
    size_t size;

    int fd = external_open(FILENAME, 0);
    if (fd == -1) {
        external_exit(1);
    }

    size = external_filesize(fd);
    file = external_filemmap(fd, size);

    external_exit(bfexec(file, size, &funcs));
}
