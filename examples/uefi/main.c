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

#include <efi.h>
#include <efilib.h>

#define BFALERT(...) Print(L"[BAREFLANK ALERT]: " __VA_ARGS__)

#include <bfexec.h>
#include <cxx_uefi.h>

/* ---------------------------------------------------------------------------*/
/* Helpers Functions                                                          */
/* ---------------------------------------------------------------------------*/

void *
platform_alloc(size_t size)
{
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS addr = 0;

    status = gBS->AllocatePages(
                 AllocateAnyPages, EfiRuntimeServicesCode, (size / EFI_PAGE_SIZE) + 1, &addr
             );

    if (EFI_ERROR(status)) {
        BFALERT("platform_alloc: AllocatePages failed: %lld\n", size);
    }

    return (void *)addr;
}

void
platform_free(void *ptr, size_t size)
{
    gBS->FreePages(
        (EFI_PHYSICAL_ADDRESS) ptr, (size / EFI_PAGE_SIZE) + 1
    );
}

status_t
platform_mark_rx(void *addr, size_t size)
{
    bfignored(addr);
    bfignored(size);

    return BFSUCCESS;
}

void
platform_syscall_write(struct bfsyscall_write_args *args)
{
    size_t i = 0;

    switch(args->fd) {
        case 1:
        case 2:
            for (i = 0; i < args->nbyte; i++) {
                Print(L"%c", ((char *)args->buf)[i]);
            }
            args->ret = args->nbyte;
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

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    InitializeLib(image, systab);

    Print(L"\n");
    Print(L"  ___                __ _           _   \n");
    Print(L" | _ ) __ _ _ _ ___ / _| |__ _ _ _ | |__\n");
    Print(L" | _ \\/ _` | '_/ -_)  _| / _` | ' \\| / /\n");
    Print(L" |___/\\__,_|_| \\___|_| |_\\__,_|_||_|_\\_\\\n");
    Print(L"\n");
    Print(L" Please give us a star on: https://github.com/Bareflank/standalone_cxx\n");
    Print(L"\n");

    return bfexec((char *)cxx_uefi, cxx_uefi_len, &funcs);
}
