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

/* -------------------------------------------------------------------------- */
/* Binary Includes                                                            */
/* -------------------------------------------------------------------------- */

extern void *file;
extern size_t file_size;
extern struct bfelf_file_t *ef;

/* -------------------------------------------------------------------------- */
/* Alloc Function                                                             */
/* -------------------------------------------------------------------------- */

void *
platform_alloc(size_t size)
{
    EFI_STATUS status;
    EFI_PHYSICAL_ADDRESS addr = 0;

    if ((size & (EFI_PAGE_SIZE - 1)) != 0) {
        BFALERT("platform_alloc: size is not a multiple of a page\n");
        return nullptr;
    }

    status = gBS->AllocatePages(
                 AllocateAnyPages, EfiRuntimeServicesCode, (size / EFI_PAGE_SIZE), &addr
             );

    if (EFI_ERROR(status)) {
        BFALERT("platform_alloc: AllocatePages failed: %lld\n", size);
        return nullptr;
    }

    return (void *)addr;
}

/* ---------------------------------------------------------------------------*/
/* Helpers Functions                                                          */
/* ---------------------------------------------------------------------------*/

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

/* -------------------------------------------------------------------------- */
/* Implementation                                                             */
/* -------------------------------------------------------------------------- */

EFI_STATUS
efi_main(EFI_HANDLE image, EFI_SYSTEM_TABLE *systab)
{
    InitializeLib(image, systab);

    /*
     * The following are the arguments that we pass to bfexec. Since we did not
     * define the BFINCLUDE_ALLOCATIONS macro, we need to tell bfexec to to this
     * for us manually for the TLS block, stack and heap. Since the ELF file
     * was loaded prior to being embedded into this app, we do not need to
     * allocate memory for the ELF file like the loader example, but a TLS
     * block, stack and heap are still needed, and we do not want to statically
     * allocate this in the app like we do with the other loader example as the
     * UEFI app would place this into the app (not BSS) which would make it
     * huge.
     */
    struct _start_args_t args = {
        .alloc = platform_alloc,
        .syscall = platform_syscall
    };

    /*
     * We have to set the ef->exec to a nullptr as it has the exec location
     * from the loader. By setting it to 0, the ELF loader will automatically
     * use exec to the "virt" parameter that is provided below.
     */
    ef->exec = nullptr;
    if (bfelf_file_relocate(ef, (uint64_t)file) != BFSUCCESS) {
        return 1;
    }

    /*
     * Finally, we just call the bfexecs function, which will execute the C++
     * code for us from the loader. Note that the only allocations are for the
     * heap, stack and TLS block. We do not need to alloc memory for the ELF
     * file itself because we already did that work with the compile phase.
     */
    return bfexecs(ef, &args);
}
