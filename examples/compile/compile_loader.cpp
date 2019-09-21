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

#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <tuple>
#include <string>
#include <fstream>

#include <bfelf_loader.h>

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
// The Guts
// -----------------------------------------------------------------------------

// Main
//
// Arguments
//
// 1: ELF file
// 2: output file
// 2: output file (for ELF structure)
//
int main(int argc, char *argv[])
{
    if (argc != 4) {
        throw std::runtime_error("wrong number of arguments");
        exit(1);
    }

    // -------------------------------------------------------------------------
    // Map files

    auto [file, file_size, file_fd] = map_file(argv[1]);

    // -------------------------------------------------------------------------
    // Convert ELF to flat binary

    struct bfelf_file_t ef;
    if (bfelf_file_init(file, &ef) != BFSUCCESS) {
        throw std::runtime_error("failed to init the ELF file");
    }

    auto exec = new char[ef.size];
    if (exec == nullptr) {
        throw std::runtime_error("failed to allocate memory for the ELF file");
    }

    if (bfelf_file_load(&ef, exec, nullptr) != BFSUCCESS) {
        throw std::runtime_error("failed to load the ELF file");
    }

    munmap(file, file_size);
    close(file_fd);

    // -------------------------------------------------------------------------
    // Output the flat binary

    if (auto stream = std::fstream(argv[2], std::fstream::out | std::fstream::binary)) {
        stream.write(exec, ef.size);
    }

    if (auto stream = std::fstream(argv[3], std::fstream::out | std::fstream::binary)) {
        stream.write(reinterpret_cast<char *>(&ef), sizeof(struct bfelf_file_t));
    }

    delete [] exec;

    // -------------------------------------------------------------------------
    // Done

    return 0;
}
