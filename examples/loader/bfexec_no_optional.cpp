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

#include <cstdlib>

void *
platform_alloc(size_t size)
{
    if (auto ptr = aligned_alloc(0x20000, size)) {
        if (mprotect(ptr, size, PROT_READ|PROT_WRITE|PROT_EXEC) == 0) {
            return ptr;
        }
    }

    return nullptr;
}

bfexec_funcs_t funcs = {
    .alloc = platform_alloc
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

    return bfexec(file.data(), &funcs);
}
