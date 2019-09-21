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

/**
 * @file bfelf_loader.h
 *
 * Motivation:
 *
 * We need a way to load an ELF executable as shellcode from both the Linux and
 * Windows kernels as well as UEFI. At the time of writing, there wasn't a
 * header-only library designed to load ELF executables that doesn't have
 * dependencies on an OS. The goal of this ELF loader is to provide such
 * support with the following features:
 * - Capable of loading ELF executables in any C/C++ environment
 * - Header-only
 * - Well tested and statically/dynamically analyzed.
 *
 * There are some limitations:
 * - The ELF exectuable must be compiled as a static PIE. Note that this does
 *   not mean or support the use of GCC's "-static-pie" option. This option
 *   is a GCC/Linux specific thing designed to add libgcc functionality to the
 *   resulting executable which performs the relocations itself. This code
 *   relies on OS level stuff that we do not/can not use. Instead, this library
 *   assumes that the ELF executable was compiled using a freestanding
 *   environment, and as such, this ELF loader provides the logic to perform
 *   the needed relocations prior to execution. For this reason, we assume that
 *   linking is handled manually by the user and the following flags were
 *   used at a minimum:
 *   GCC/Clang: -fpic
 *   LD: --no-dynamic-linker -nostdlib -pie -static
 *
 * - R_xxx_RELATIVE is the only relocation type that is currently supported.
 *   This relocation type is simple and doesn't require symbol information.
 *   Instead, it simply needs the load offset for the position independent
 *   executable.
 *
 * - Memory allocation (or mapping) must be provided. In other ELF loader
 *   implementations, you pass the ELF file to it, and boom... you have a
 *   working ELF executable. This is not the case with this library as RE
 *   memory is needed. How this memory is allocated and mapped depends on the
 *   OS. So, this library breaks the load option into two steps. The first step
 *   initializes an internal ELF structure with information about the ELF file.
 *   The user then allocates the needed memory. The second and final step loads
 *   the ELF file into the allocated memory and then performs the needed
 *   relocations and mprotect functions.
 *
 * - Since this is C code, there really is no way to validate that the user
 *   isn't using the APIs properly. This includes dumb things like allocating
 *   the wrong sized memory, passing invalid pointers, etc... To handle this
 *   issue, we test the hell out of the code including 100% unit test coverage,
 *   static/dynamic analysis, etc...
 *
 * - There are some limitations on what types of ELF files this loader will
 *   except. These limitation include:
 *   - We only support a single RE and a single RW PT_LOAD segment. If there are
 *     more, or if the segments are labeled RWE, we do not support that
 *     type of ELF file currently.
 *   - We only support a single RELA section. REL sections are not supported.
 *     Furthermore, the only relocation type that we support is R_xxx_RELATIVE.
 *   - We do not support the legacy init, fini, ctors and dtors sections.
 *   - We only support read/write stacks. Execution rights on the stack are
 *     not supported.
 *   - In general, the ELF loader is picky about the types of sections, and
 *     segments the the ELF file can have, specifically to ensure the ELF file
 *     was created properly. These restrictions can be lifted over time,
 *     depending on how complex this header-only library needs to get.
 */

#ifndef BFELF_LOADER_H
#define BFELF_LOADER_H

#include "bfelf_loader_private.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @struct bfelf_file_t
 *
 * The bfelf_file_t structure is used to store information about the ELF file
 * that is useful/needed by the user of these APIs, as well as store internal
 * private state that should not be used by the user. That "public" fields in
 * this structure are as follows. All other fields should be ignored as they
 * are subject to change.
 *
 * @var bfelf_file_t::exec
 *      a ptr to the ELF executable in memory. This might be nullptr.
 * @var bfelf_file_t::size
 *      the size of the ELF executable in memory.
 * @var bfelf_file_t::entry
 *      the _start function for the ELF exectuable
 * @var bfelf_file_t::init_array_addr
 *      the address of the init array section
 * @var bfelf_file_t::init_array_size
 *      the size of the init array section
 * @var bfelf_file_t::fini_array_addr
 *      the address of the fini array section
 * @var bfelf_file_t::fini_array_size
 *      the size of the fini array section
 * @var bfelf_file_t::eh_frame_addr
 *      the address of the eh_frame section
 * @var bfelf_file_t::eh_frame_size
 *      the size of the eh_frame section
 */

/**
 * Initialize an ELF file
 *
 * This function checks to make sure the ELF file is valid and then gets the
 * the total size of the executable memory the ELF file will need. If this
 * function returns BFSUCCESS, use ef.size to allocate memory for the ELF file
 * and then run bfelf_file_load() and bfelf_file_relocate() (if the ELF file
 * was compiled with -fpie).
 *
 * For example:
 *
 * @code
 * struct bfelf_file_t ef;
 * bfelf_file_init(file, &ef);
 * void *exec = malloc(ef.size);
 * bfelf_file_load(&ef, exec, nullptr);
 * bfelf_file_relocate(&ef, 0);
 * free(exec);
 * @endcode
 *
 * In the example above, we initialize the ELF file and then allocate memory
 * for the "exec", which is the memory that the ELF file will be executed from.
 * To execute the "exec", the read/execute portions of the ELF file in "exec"
 * must be marked as read/execute. There are two ways to handle this:
 * - In your custom allocation function, allocate the memory and then set the
 *   entire buffer to RWE. This will ensure that the memory has the proper
 *   privileges to execute no matter how it is layed out. The problem with this
 *   approach is that it is not as secure.
 * - Provide a mark_rx function to the bfelf_file_load() function which will
 *   mark the read/execute portion of the "exec" as needed. Note that on most
 *   operating systems, your custom allocation function will need to return
 *   aligned memory (the alignment depends on the CPU architecture and OS), as
 *   most mprotect functions require aligned memory.
 * Finally, in our example above, we call the bfelf_file_load() function which
 * loads the ELF file (i.e., it puts the ELF file into the exec buffer in the
 * right location). This function also stores some offset information for
 * sections in the ELF file. Finally, run the bfelf_file_relocate() function if
 * the ELF file was compiled and linked with -fpie (i.e., the resulting binary
 * is position independent).
 *
 * @expects file != nullptr
 * @expects ef != nullptr
 * @ensures
 *
 * @param file a character buffer containing the contents of the ELF file to
 *     be loaded.
 * @param ef a pointer to the bfelf_file_t structure which stores information
 *     about the ELF file being loaded.
 * @return BFSUCCESS on success, BFFAILURE on error
 */
static inline status_t
bfelf_file_init(const void *file, struct bfelf_file_t *ef);

/**
 * Load an ELF file
 *
 * This function loads the ELF file that was previously initialized using the
 * bfelf_file_init function. The main purpose of the bfelf_file_init function
 * is to make sure the ELF file is valid, to store some private internal state
 * and then populate the "size" field so that the user of these APIs knows
 * how much memory to allocate. The ELF file itself cannot be directly
 * executed and instead must be loaded into memory based on instructions
 * provided by the ELF file's program headers. This API forces the user to
 * allocate this memory for the APIs as allocating memory is platform
 * specific. Once this memory is allocated, this function can be called which
 * will actually load the ELF file into memory so that it can be executed.
 *
 * Besides providing the bfelf_file_t that was initialied using the
 * bfelf_file_init() function, this function takes some additional parameters.
 * The first, "exec" is the address to the memory that must be allocated
 * by the user. Finally, this function allows you to pass a mark_rx function
 * which will be called to mark a portion of the "exec" memory as read/execute.
 * If your memory was allocated as RWE, this function is not needed and you can
 * safely pass a nullptr instead. If your memory was allocated as RW, which is
 * the case with malloc, you will need to pass a mark_rx function that provides
 * the API with the ability to mark a portion of the "exec" memory as RE. If
 * a mark_rx function is needed, you will likely need to allocate aligned
 * memory to ensure the memory being marked is properly aligned.
 *
 * @expects ef != nullptr
 * @expects exec != nullptr
 * @ensures
 *
 * @param ef the ELF file structure to initialize.
 * @param exec a buffer of memory the size of "ef.size" with RWE privileges.
 * @param mark_rx a mprotect function to mark a region of memory as read/execute
 * @return BFSUCCESS on success, BFFAILURE on error
 */
static inline status_t
bfelf_file_load(struct bfelf_file_t *ef, void *exec, status_t (*mark_rx_func)(void *, size_t));

/**
 * Relocate and ELF file
 *
 * This function relocate the ELF file. This is only needed if the ELF file was
 * compiled with "-fpie". There are two important notes WRT to this function:
 * - If the virtual address that the "exec" will execute from is different than
 *   the "exec" itself, you can provide this address and the APIs will use that
 *   address when relocating. If they are the same, you can just pass 0.
 * - This function can be executed by both the loader and the runtime. That is,
 *   you can run this from the exec itself, prior to entering the ELF file.
 *   You just need to copy the bfelf_file_t structure so that you have it to
 *   run this API. If you plan to do this, make sure you 0 out the exec in the
 *   structure prior to running this API, which will force the exec to be equal
 *   to the virtual address you provide.
 *
 * @expects ef != nullptr
 * @ensures
 *
 * @param ef the ELF file structure to initialize.
 * @param virt the virtual address the exec will run from
 * @return BFSUCCESS on success, BFFAILURE on error
 */
static inline status_t
bfelf_file_relocate(struct bfelf_file_t *ef, bfelf64_addr virt);

#ifdef __cplusplus
}
#endif

#endif
