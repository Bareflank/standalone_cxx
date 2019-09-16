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

#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <tuple>
#include <string>
#include <array>
#include <fstream>
#include <iostream>

// -----------------------------------------------------------------------------
// Macros
// -----------------------------------------------------------------------------

#define BUFFER_SIZE 0x2000

// -----------------------------------------------------------------------------
// Map File
// -----------------------------------------------------------------------------

size_t
filesize(int fd)
{
    struct stat s = {};
    if (int ret = fstat(fd, &s); ret != -1) {
        return s.st_size;
    }

    throw std::runtime_error("failed to fstat file");
}

char *
filemmap(int fd, size_t size)
{
    if (auto f = mmap(0, size, PROT_READ, MAP_PRIVATE, fd, 0); f != MAP_FAILED) {
        return static_cast<char *>(f);
    }

    throw std::runtime_error("failed to mmap file");
}


std::tuple<char *, size_t, int>
map_file(const std::string &filename)
{
    int fd = open(filename.c_str(), O_RDONLY);
    if (fd == -1) {
        throw std::runtime_error("failed to open file: " + filename);
    }

    auto size = filesize(fd);
    auto file = filemmap(fd, size);

    return {static_cast<char *>(file), size, fd};
}

// -----------------------------------------------------------------------------
// The Guts
// -----------------------------------------------------------------------------

int main(int argc, char *argv[])
{
    char buffer1[BUFFER_SIZE] = {};
    char buffer2[BUFFER_SIZE] = {};

    if (argc != 3) {
        throw std::runtime_error("wrong number of arguments");
    }

    std::cout << &buffer1 << '\n';

    auto [file1, file1_size, file1_fd] = map_file(argv[1]);
    memcpy(buffer1, file1, file1_size);

    auto [file2, file2_size, file2_fd] = map_file(argv[2]);
    memcpy(buffer2, file2, file2_size);

    if (memcmp(buffer1, buffer2, BUFFER_SIZE) == 0) {
        std::cout << "equal\n";
    }
    else {
        std::cout << "not equal\n";
    }

    return 0;
}
