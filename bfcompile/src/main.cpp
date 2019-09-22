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

#include <vector>
#include <memory>
#include <fstream>
#include <filesystem>

#include <bfelf_loader.h>

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    std::vector<char> file;

    if (argc != 4) {
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

    struct bfelf_file_t ef;
    if (bfelf_file_init(file.data(), &ef) != BFSUCCESS) {
        throw std::runtime_error("failed to init the ELF file");
    }

    auto exec = std::make_unique<char[]>(ef.size);
    if (bfelf_file_load(&ef, exec.get(), nullptr) != BFSUCCESS) {
        throw std::runtime_error("failed to load the ELF file");
    }

    if (auto strm = std::ofstream(argv[2], std::fstream::binary)) {
        strm.write(exec.get(), ef.size);
    }
    else {
        throw std::runtime_error("failed to open output file");
    }

    if (auto strm = std::ofstream(argv[3], std::fstream::binary)) {
        strm.write(reinterpret_cast<char *>(&ef), sizeof(struct bfelf_file_t));
    }
    else {
        throw std::runtime_error("failed to open output ef file");
    }

    return 0;
}
