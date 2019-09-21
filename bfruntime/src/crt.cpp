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

#include <stdlib.h>

#include <bftypes.h>
#include <bfstart.h>
#include <bfehframelist.h>
#include <bfthreadcontext.h>
#include <bfweak.h>
#include <bfsyscall.h>

#include <iostream>

// -----------------------------------------------------------------------------
// Global Resources
// -----------------------------------------------------------------------------

eh_frame_t __g_eh_frame = {};
syscall_func_t __g_syscall_func = {};

uint8_t *__g_heap = {};
uint64_t __g_heap_size = {};
uint8_t *__g_heap_cursor = {};

// -----------------------------------------------------------------------------
// Main Functions
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Original Stack Pointer Helpers
// -----------------------------------------------------------------------------

extern "C" void
_set_original_sp(uint64_t sp)
{ thread_context_ptr(__tc_tocs())->original_sp = sp; }

extern "C" uint64_t
_get_original_sp(void)
{ return thread_context_ptr(__tc_tocs())->original_sp; }

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

extern "C" status_t
_start_c(const _start_args_t *info) noexcept
{
    using init_t = void (*)();

    __g_eh_frame = {
        reinterpret_cast<void *>(info->eh_frame_addr),
        info->eh_frame_size
    };

    __g_heap = static_cast<uint8_t *>(info->heap);
    __g_heap_size = info->heap_size;
    __g_heap_cursor = static_cast<uint8_t *>(info->heap);
    __g_syscall_func = info->syscall_func;

    std::ios_base::Init mInitializer;

    if (auto funcs = reinterpret_cast<init_t *>(info->init_array_addr)) {
        auto n = info->init_array_size >> 3;
        for (auto i = 0U; i < n; i++) {
            funcs[i]();
        }
    }

    exit(main(info->argc, info->argv));

    // Only needed for debugging
    return EXIT_FAILURE;
}
