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
 * @var bfelf_file_t::entry
 *      the _start function for the ELF exectuable (filled by bfelf_file_load)
 * @var bfelf_file_t::init_array_addr
 *      the address of the init array section (filled by bfelf_file_load)
 * @var bfelf_file_t::init_array_size
 *      the size of the init array section (filled by bfelf_file_load)
 * @var bfelf_file_t::fini_array_addr
 *      the address of the fini array section (filled by bfelf_file_load)
 * @var bfelf_file_t::fini_array_size
 *      the size of the fini array section (filled by bfelf_file_load)
 * @var bfelf_file_t::eh_frame_addr
 *      the address of the eh_frame section (filled by bfelf_file_load)
 * @var bfelf_file_t::eh_frame_size
 *      the size of the eh_frame section (filled by bfelf_file_load)
 */

/**
 * Initialize an ELF file
 *
 * This function initializes an ELF file structure given the file's contents
 * in memory. The resulting structure will be used by the bfelf_file_load and
 * as a result, this function must be execute prior to executing the
 * bfelf_file_load() function.
 *
 * After executing this function, the bfelf_file structure will have the total
 * size of the memory needed by the executable stored. Therefore, the easiest
 * way to use this API is the following:
 *
 * @code
 * struct bfelf_file_t ef;
 * bfelf_file_init(file, filesz, &ef);
 * void *exec = bfelf_file_alloc(&ef, custom_alloc);
 * bfelf_file_load(exec, nullptr, &ef, nullptr);
 * custom_free(exec)
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
 *   aligned memory (the alignment depends on the CPU archiecture and OS), as
 *   most mprotect functions require aligned memory.
 * Finally, in our example above, we call the bfelf_file_load() function with
 * loads the ELF file. Once this is done, you are free to execute the ELF file
 * as needed. Also note that you must free the memory you allocated once you
 * the ELF file no longer needs to execute, and you are responsible for
 * handling language specific features like init/fini, exceptions, TLS, a
 * stack, etc... This library simply handles the ELF portions of the binary.
 *
 * @expects file != nullptr
 * @expects filesz != nullptr
 * @expects ef != nullptr
 * @ensures
 *
 * @param file a character buffer containing the contents of the ELF file to
 *     be loaded.
 * @param filesz the size of the character buffer
 * @param ef a pointer to the bfelf_file_t structure which stores information
 *     about the ELF file being loaded.
 * @return ELF_SUCCESS on success, negative on error
 */
static inline status_t
bfelf_file_init(const void *file, uint64_t filesz, struct bfelf_file_t *ef);

/**
 * Allocate ELF File Memory
 *
 * This function requires that you provide it with a custom allocation
 * function. Generally speaking, this can be done as follows:
 *
 * @code
 * void *
 * custom_alloc(size_t size)
 * { return aligned_alloc(0x1000, size); }
 * @endcode
 *
 * The above example assumes that you provide the bfelf_file_load() function
 * with a custom mprotect function, and that your OS will mprotect memory with
 * a minimum alignment of 0x1000 (a 4k page). If your OS or CPU does not
 * match these assumptions, you will likely need to adjust as needed.
 *
 * For example:
 *
 * @code
 * status_t
 * custom_mprotect(void *addr, size_t size)
 * {
 *     if (mprotect(addr, size, PROT_READ|PROT_EXEC) != 0) {
 *         return BFFAILURE;
 *     }
 *
 *     return BFSUCCESS;
 * }
 * @endcode
 *
 * The custom mprotect function that is provided above can be used by the
 * bfelf_file_load() function to mark a specific portion of the allocated
 * memory to read/execute. Both the allocation and the mprotect functions
 * must corrdinate to ensure the memory that is allocated can successfully
 * be protected.
 *
 * Another approach to implementing this function would look like the
 * following:
 *
 * @code
 * void *
 * custom_alloc(size_t size)
 * {
 *     void *ptr = aligned_alloc(0x1000, size);
 *
 *     if (mprotect(ptr, size, PROT_READ|PROT_WRITE|PROT_EXEC) != 0) {
 *         free(ptr);
 *         return nullptr;
 *     }
 *
 *     return ptr;
 * }
 * @endcode
 *
 * The above example removes the need to pass a custom mprotect function to
 * the bfelf_file_load() function, but marks the entire ELF file as RWE,
 * which is typically a bad idea as this is less secure.
 *
 * @param alloc_func the custom allocation function to use
 * @return returns a pointer to the newly allocated memory, NULL on error.
 */
static inline void *
bfelf_file_alloc(struct bfelf_file_t *ef, void *(*alloc_func)(size_t));

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
 * by the user. The "virt" parameter is needed because if the ELF file needs to
 * be relocated, the address that the ELF file is being relocated might not
 * be the same address as "exec". In most cases,"exec" and "virt" are the same,
 * and you can pass a nullptr and the APIs will adjust as needed. If however
 * you are using the ELF loader in a custom kernel or hypervisor, and the
 * executable will be executing with a virtual address (i.e. its own pages
 * tables) that is different from the virtual address that is being used to
 * initialize the executables memory, you must set "virt" to the starting
 * address of the executable as the executable would see it. This ensures that
 * all of the relocations are performed using the memory space the executable
 * expects to see, and not the one that was used to load the executable.
 * Finally, this function allows you to pass a mark_rx function which will be
 * called to mark a portion of the "exec" memory as read/execute. See the
 * allocation function for more information.
 *
 * @expects exec != nullptr
 * @expects ef != nullptr
 * @ensures
 *
 * @param exec a buffer of memory the size of "ef.size" with RWE privileges.
 * @param virt the virtual address the executable will be relocated to.
 * @param ef the ELF file structure to initialize.
 * @param mark_rx a mprotect function to mark a region of memory as read/execute
 * @return ELF_SUCCESS on success, negative on error
 */
static inline status_t
bfelf_file_load(
    void *exec, bfelf64_addr virt, struct bfelf_file_t *ef, status_t (*mark_rx_func)(void *, size_t));

#ifdef __cplusplus
}
#endif

#endif
