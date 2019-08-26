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

#include <bftypes.h>
#include <bfstart.h>
#include <bfehframelist.h>
#include <bfthreadcontext.h>
#include <bfweak.h>
#include <bfsyscall.h>

/* ---------------------------------------------------------------------------*/
/* Global Resources                                                           */
/* ---------------------------------------------------------------------------*/

eh_frame_t __g_eh_frame = {};
syscall_func_t __g_syscall_func = {};

/* ---------------------------------------------------------------------------*/
/* Default Stack/TLS Blocks                                                   */
/* ---------------------------------------------------------------------------*/

uint8_t __g_stack[BFSTACK_SIZE] = {};
uint8_t __g_tls_block[BFTLS_SIZE] = {};

/* ---------------------------------------------------------------------------*/
/* Main Functions                                                             */
/* ---------------------------------------------------------------------------*/

WEAK_SYM int
main(int argc, char *argv[])
{
    bfignored(argc);
    bfignored(argv);

    return -1;
}

WEAK_SYM int
main()
{ return main(0, nullptr); }

WEAK_SYM status_t
bfmain(uint64_t request, uint64_t arg1, uint64_t arg2)
{
    bfignored(request);
    bfignored(arg1);
    bfignored(arg2);

    return -1;
}

/* ---------------------------------------------------------------------------*/
/* Implementation                                                             */
/* ---------------------------------------------------------------------------*/

static inline void
__bareflank_init_fini(uint64_t addr, uint64_t size) noexcept
{
    using init_fini_t = void (*)();

    auto n = size >> 3;
    auto init_fini_funcs = reinterpret_cast<init_fini_t *>(addr);

    if (init_fini_funcs == nullptr) {
        return;
    }

    for (auto i = 0U; i < n && init_fini_funcs[i] != nullptr; i++) {
        init_fini_funcs[i]();
    }
}

static inline void
__bareflank_set_global_resources(const _start_args_t *info) noexcept
{
    __g_eh_frame.addr = reinterpret_cast<void *>(info->eh_frame_addr);
    __g_eh_frame.size = info->eh_frame_size;
    __g_syscall_func = info->syscall_func;
}

extern "C" status_t
_start_c(const _start_args_t *info) noexcept
{
    status_t ret = 0;

    if (info->request == 0 || info->request == BFMAIN_REQUEST_INIT) {
        __bareflank_set_global_resources(info);
        __bareflank_init_fini(info->init_array_addr, info->init_array_size);

        if (info->request == BFMAIN_REQUEST_INIT) {
            return BFSUCCESS;
        }
    }

    if (info->request == 0) {
        ret = main(info->argc, info->argv);
    }
    else {
        ret = bfmain(info->request, info->arg1, info->arg2);
    }

    if (info->request == 0 || info->request == BFMAIN_REQUEST_FINI) {
        __bareflank_init_fini(info->fini_array_addr, info->fini_array_size);

        if (info->request == BFMAIN_REQUEST_FINI) {
            return BFSUCCESS;
        }
    }

    return ret;
}
