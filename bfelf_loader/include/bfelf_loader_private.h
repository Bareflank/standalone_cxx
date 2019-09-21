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

#ifndef BFELF_LOADER_PRIVATE_H
#define BFELF_LOADER_PRIVATE_H

#include <bftypes.h>

#pragma pack(push, 1)

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------------------------------------------------------- */
/* Debugging                                                                  */
/* -------------------------------------------------------------------------- */

#ifndef BFALERT

#if !defined(KERNEL)

#ifdef __cplusplus
#include <cstdio>
#else
#include <stdio.h>
#endif
#define BFALERT(...) printf("[BAREFLANK ALERT]: " __VA_ARGS__)

#else

#ifdef __linux__
#include <linux/printk.h>
#define BFALERT(...) printk(KERN_INFO "[BAREFLANK ALERT]: " __VA_ARGS__)
#endif

#ifdef _WIN32
#include <wdm.h>
#define BFALERT(...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[BAREFLANK ALERT]: " __VA_ARGS__)
#endif

#endif

#endif

/* -------------------------------------------------------------------------- */
/* ELF Data Types                                                             */
/* -------------------------------------------------------------------------- */

/*
 * Data Representation
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 2
 */

#ifndef __cplusplus
typedef uint64_t bfelf64_addr;
typedef uint64_t bfelf64_off;
typedef uint16_t bfelf64_half;
typedef uint32_t bfelf64_word;
typedef int32_t bfelf64_sword;
typedef uint64_t bfelf64_xword;
typedef int64_t bfelf64_sxword;
#else
using bfelf64_addr = uint64_t;
using bfelf64_off = uint64_t;
using bfelf64_half = uint16_t;
using bfelf64_word = uint32_t;
using bfelf64_sword = int32_t;
using bfelf64_xword = uint64_t;
using bfelf64_sxword = int64_t;
#endif

/* -------------------------------------------------------------------------- */
/* ELF File Definition                                                        */
/* -------------------------------------------------------------------------- */

struct bfelf_shdr;
struct bfelf_ehdr;

struct bfelf_file_t {

    const uint8_t *file;
    const struct bfelf_ehdr *ehdr;

    uint8_t *exec;
    size_t size;

    bfelf64_addr entry;

    bfelf64_addr rela_array_addr;
    bfelf64_xword rela_array_size;

    bfelf64_addr init_array_addr;
    bfelf64_xword init_array_size;

    bfelf64_addr fini_array_addr;
    bfelf64_xword fini_array_size;

    bfelf64_addr eh_frame_addr;
    bfelf64_xword eh_frame_size;
};

/* -------------------------------------------------------------------------- */
/* ELF File Header                                                            */
/* -------------------------------------------------------------------------- */

/*
 * e_ident indexes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 3
 */

#define bfei_mag0 BFSCAST(bfelf64_sword, 0)
#define bfei_mag1 BFSCAST(bfelf64_sword, 1)
#define bfei_mag2 BFSCAST(bfelf64_sword, 2)
#define bfei_mag3 BFSCAST(bfelf64_sword, 3)
#define bfei_class BFSCAST(bfelf64_sword, 4)
#define bfei_data BFSCAST(bfelf64_sword, 5)
#define bfei_version BFSCAST(bfelf64_sword, 6)
#define bfei_osabi BFSCAST(bfelf64_sword, 7)
#define bfei_abiversion BFSCAST(bfelf64_sword, 8)
#define bfei_pad BFSCAST(bfelf64_sword, 9)
#define bfei_nident BFSCAST(bfelf64_sword, 16)

/*
 * ELF Class Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */

#define bfelfclass32 BFSCAST(unsigned char, 1)
#define bfelfclass64 BFSCAST(unsigned char, 2)

/*
 * ELF Data Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */

#define bfelfdata2lsb BFSCAST(unsigned char, 1)
#define bfelfdata2msb BFSCAST(unsigned char, 2)

/*
 * ELF Version
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 4
 */

#define bfev_current BFSCAST(unsigned char, 1)

/*
 * ELF OS / ABI Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */

#define bfelfosabi_sysv BFSCAST(unsigned char, 0)
#define bfelfosabi_hpux BFSCAST(unsigned char, 1)
#define bfelfosabi_standalone BFSCAST(unsigned char, 255)

/*
 * ELF Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 5
 */

#define bfet_none BFSCAST(bfelf64_half, 0)
#define bfet_rel BFSCAST(bfelf64_half, 1)
#define bfet_exec BFSCAST(bfelf64_half, 2)
#define bfet_dyn BFSCAST(bfelf64_half, 3)
#define bfet_core BFSCAST(bfelf64_half, 4)
#define bfet_loos BFSCAST(bfelf64_half, 0xFE00)
#define bfet_hios BFSCAST(bfelf64_half, 0xFEFF)
#define bfet_loproc BFSCAST(bfelf64_half, 0xFF00)
#define bfet_hiproc BFSCAST(bfelf64_half, 0xFFFF)

/*
 * ELF Machine Codes
 *
 * The following is defined in the Linux kernel sources:
 * linux/include/uapi/linux/elf-em.h
 */

#define bfem_none BFSCAST(bfelf64_half, 0)
#define bfem_m32 BFSCAST(bfelf64_half, 1)
#define bfem_sparc BFSCAST(bfelf64_half, 2)
#define bfem_386 BFSCAST(bfelf64_half, 3)
#define bfem_68k BFSCAST(bfelf64_half, 4)
#define bfem_88k BFSCAST(bfelf64_half, 5)
#define bfem_486 BFSCAST(bfelf64_half, 6)
#define bfem_860 BFSCAST(bfelf64_half, 7)
#define bfem_mips BFSCAST(bfelf64_half, 8)
#define bfem_mips_rs3_le BFSCAST(bfelf64_half, 10)
#define bfem_mips_rs4_be BFSCAST(bfelf64_half, 11)
#define bfem_parisc BFSCAST(bfelf64_half, 15)
#define bfem_sparc32plus BFSCAST(bfelf64_half, 18)
#define bfem_ppc BFSCAST(bfelf64_half, 20)
#define bfem_ppc64 BFSCAST(bfelf64_half, 21)
#define bfem_spu BFSCAST(bfelf64_half, 23)
#define bfem_arm BFSCAST(bfelf64_half, 40)
#define bfem_sh BFSCAST(bfelf64_half, 42)
#define bfem_sparcv9 BFSCAST(bfelf64_half, 43)
#define bfem_h8_300 BFSCAST(bfelf64_half, 46)
#define bfem_ia_64 BFSCAST(bfelf64_half, 50)
#define bfem_x86_64 BFSCAST(bfelf64_half, 62)
#define bfem_s390 BFSCAST(bfelf64_half, 22)
#define bfem_cris BFSCAST(bfelf64_half, 76)
#define bfem_v850 BFSCAST(bfelf64_half, 87)
#define bfem_m32r BFSCAST(bfelf64_half, 88)
#define bfem_mn10300 BFSCAST(bfelf64_half, 89)
#define bfem_openrisc BFSCAST(bfelf64_half, 92)
#define bfem_blackfin BFSCAST(bfelf64_half, 106)
#define bfem_altera_nios2 BFSCAST(bfelf64_half, 113)
#define bfem_ti_c6000 BFSCAST(bfelf64_half, 140)
#define bfem_aarch64 BFSCAST(bfelf64_half, 183)
#define bfem_frv BFSCAST(bfelf64_half, 0x5441)
#define bfem_avr32 BFSCAST(bfelf64_half, 0x18AD)
#define bfem_alpha BFSCAST(bfelf64_half, 0x9026)
#define bfem_cygnus_v850 BFSCAST(bfelf64_half, 0x9080)
#define bfem_cygnus_m32r BFSCAST(bfelf64_half, 0x9041)
#define bfem_s390_old BFSCAST(bfelf64_half, 0xA390)
#define bfem_cygnus_mn10300 BFSCAST(bfelf64_half, 0xBEEF)

/*
 * ELF File Header
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 3
 *
 * The file header is located at the beginning of the file, and is used to
 * locate the other parts of the file.
 */

struct bfelf_ehdr {
    unsigned char e_ident[bfei_nident];
    bfelf64_half e_type;
    bfelf64_half e_machine;
    bfelf64_word e_version;
    bfelf64_addr e_entry;
    bfelf64_off e_phoff;
    bfelf64_off e_shoff;
    bfelf64_word e_flags;
    bfelf64_half e_ehsize;
    bfelf64_half e_phentsize;
    bfelf64_half e_phnum;
    bfelf64_half e_shentsize;
    bfelf64_half e_shnum;
    bfelf64_half e_shstrndx;
};

/* -------------------------------------------------------------------------- */
/* ELF Section Header (ELF Section)                                           */
/* -------------------------------------------------------------------------- */

/*
 * ELF Section Type
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 7
 */

#define bfsht_null BFSCAST(bfelf64_word, 0)
#define bfsht_progbits BFSCAST(bfelf64_word, 1)
#define bfsht_symtab BFSCAST(bfelf64_word, 2)
#define bfsht_strtab BFSCAST(bfelf64_word, 3)
#define bfsht_rela BFSCAST(bfelf64_word, 4)
#define bfsht_hash BFSCAST(bfelf64_word, 5)
#define bfsht_dynamic BFSCAST(bfelf64_word, 6)
#define bfsht_note BFSCAST(bfelf64_word, 7)
#define bfsht_nobits BFSCAST(bfelf64_word, 8)
#define bfsht_rel BFSCAST(bfelf64_word, 9)
#define bfsht_shlib BFSCAST(bfelf64_word, 10)
#define bfsht_dynsym BFSCAST(bfelf64_word, 11)
#define bfsht_init_array BFSCAST(bfelf64_word, 14)
#define bfsht_fini_array BFSCAST(bfelf64_word, 15)
#define bfsht_loos BFSCAST(bfelf64_word, 0x60000000)
#define bfsht_hios BFSCAST(bfelf64_word, 0x6FFFFFFF)
#define bfsht_loproc BFSCAST(bfelf64_word, 0x70000000)
#define bfsht_x86_64_unwind BFSCAST(bfelf64_word, 0x70000001)
#define bfsht_hiproc BFSCAST(bfelf64_word, 0x7FFFFFFF)

/*
 * ELF Section Attributes
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 8
 */

#define bfshf_write BFSCAST(bfelf64_xword, 0x1)
#define bfshf_alloc BFSCAST(bfelf64_xword, 0x2)
#define bfshf_execinstr BFSCAST(bfelf64_xword, 0x4)
#define bfshf_maskos BFSCAST(bfelf64_xword, 0x0F000000)
#define bfshf_maskproc BFSCAST(bfelf64_xword, 0xF0000000)
#define bfshf_undocumneted BFSCAST(bfelf64_xword, 0x00000060)

#define bfshf_a (bfshf_alloc)
#define bfshf_wa (bfshf_write | bfshf_alloc)
#define bfshf_ai (bfshf_alloc | bfshf_write | bfshf_undocumneted)

/*
 * ELF Section Header Entry
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 6
 *
 * Sections contain all the information in an ELF file, except for the ELF
 * header, program header table, and section header table. Sections are
 * identified by an index into the section header table.
 */

struct bfelf_shdr {
    bfelf64_word sh_name;
    bfelf64_word sh_type;
    bfelf64_xword sh_flags;
    bfelf64_addr sh_addr;
    bfelf64_off sh_offset;
    bfelf64_xword sh_size;
    bfelf64_word sh_link;
    bfelf64_word sh_info;
    bfelf64_xword sh_addralign;
    bfelf64_xword sh_entsize;
};

/* -------------------------------------------------------------------------- */
/* ELF Program Header (ELF Segment)                                           */
/* -------------------------------------------------------------------------- */

/*
 * ELF Segment Types
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 12
 */

#define bfpt_null BFSCAST(bfelf64_word, 0)
#define bfpt_load BFSCAST(bfelf64_word, 1)
#define bfpt_dynamic BFSCAST(bfelf64_word, 2)
#define bfpt_interp BFSCAST(bfelf64_word, 3)
#define bfpt_note BFSCAST(bfelf64_word, 4)
#define bfpt_shlib BFSCAST(bfelf64_word, 5)
#define bfpt_phdr BFSCAST(bfelf64_word, 6)
#define bfpt_loos BFSCAST(bfelf64_word, 0x60000000)
#define bfpt_gnu_eh_frame BFSCAST(bfelf64_word, 0x6474e550)
#define bfpt_gnu_stack BFSCAST(bfelf64_word, 0x6474e551)
#define bfpt_gnu_relro BFSCAST(bfelf64_word, 0x6474e552)
#define bfpt_hios BFSCAST(bfelf64_word, 0x6FFFFFFF)
#define bfpt_loproc BFSCAST(bfelf64_word, 0x70000000)
#define bfpt_hiproc BFSCAST(bfelf64_word, 0x7FFFFFFF)

/*
 * ELF Segment Flags
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 13
 */

#define bfpf_x BFSCAST(bfelf64_xword, 0x1)
#define bfpf_w BFSCAST(bfelf64_xword, 0x2)
#define bfpf_r BFSCAST(bfelf64_xword, 0x4)
#define bfpf_rx (bfpf_r | bfpf_x)
#define bfpf_rw (bfpf_r | bfpf_w)
#define bfpf_maskos BFSCAST(bfelf64_xword, 0x00FF0000)
#define bfpf_maskproc BFSCAST(bfelf64_xword, 0xFF000000)

/*
 * ELF Program Header Entry
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 12
 *
 * In executable and shared object files, sections are grouped into segments for
 * loading. The program header table contains a list of entries describing
 * each segment. This information is needed when using the ELF loader to
 * load each segment into memory allocated by the user. For more information
 * on how to do this, please see the unit tests.
 */

struct bfelf_phdr {
    bfelf64_word p_type;
    bfelf64_word p_flags;
    bfelf64_off p_offset;
    bfelf64_addr p_vaddr;
    bfelf64_addr p_paddr;
    bfelf64_xword p_filesz;
    bfelf64_xword p_memsz;
    bfelf64_xword p_align;
};

/* -------------------------------------------------------------------------- */
/* ELF Relocations                                                            */
/* -------------------------------------------------------------------------- */

/*
 * ELF Relocation Addend
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 */

struct bfelf_rela {
    bfelf64_addr r_offset;
    bfelf64_xword r_info;
    bfelf64_sxword r_addend;
};

/*
 * ELF Relocation Info Algorithms
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.uclibc.org/docs/elf-64-gen.pdf, page 11
 */

#define BFELF_REL_SYM(i) ((i) >> 32)
#define BFELF_REL_TYPE(i) ((i)&0xFFFFFFFFL)

/*
 * System V ABI 64bit Relocations
 *
 * The following is defined in the ELF 64bit file format specification:
 * http://www.x86-64.org/documentation/abi.pdf, page 71
 *
 * @cond
 */

#define BFR_X86_64_64 BFSCAST(bfelf64_xword, 1)
#define BFR_X86_64_GLOB_DAT BFSCAST(bfelf64_xword, 6)
#define BFR_X86_64_JUMP_SLOT BFSCAST(bfelf64_xword, 7)
#define BFR_X86_64_RELATIVE BFSCAST(bfelf64_xword, 8)

/* -------------------------------------------------------------------------- */
/* ELF Helpers (External)                                                     */
/* -------------------------------------------------------------------------- */

#ifndef BFELF_LOADER_STRCMP
static inline status_t
private_strcmp(const char *s1, const char *s2)
{
    while ((*s1 != 0) && (*s1 == *s2)) {
        s1++, s2++;
    }

    return *s1 == *s2 ? BFSUCCESS : BFFAILURE;
}
#else
#define private_strcmp BFELF_LOADER_STRCMP
#endif

#ifndef BFELF_LOADER_MEMCPY
static inline void
private_memcpy(void *dst, const void *src, bfelf64_xword size)
{
    bfelf64_xword i;

    for (i = 0; i < size; i++) {
        BFSCAST(uint8_t *, dst)[i] = BFSCAST(const uint8_t *, src)[i];
    }
}
#else
#define private_memcpy BFELF_LOADER_MEMCPY
#endif

#ifndef BFELF_LOADER_MEMSET
static inline void
private_memset(void *dst, uint8_t val, bfelf64_xword size)
{
    bfelf64_xword i;

    for (i = 0; i < size; i++) {
        BFRCAST(uint8_t *, dst)[i] = val;
    }
}
#else
#define private_memset BFELF_LOADER_MEMSET
#endif

/* -------------------------------------------------------------------------- */
/* ELF Helpers (Internal)                                                     */
/* -------------------------------------------------------------------------- */

const struct bfelf_shdr *
private_shdrtab(
    struct bfelf_file_t *ef)
{ return BFRCAST(const struct bfelf_shdr *, ef->file + ef->ehdr->e_shoff); }

const struct bfelf_phdr *
private_phdrtab(
    struct bfelf_file_t *ef)
{ return BFRCAST(const struct bfelf_phdr *, ef->file + ef->ehdr->e_phoff); }

const char *
private_shstrtab(
    struct bfelf_file_t *ef)
{ return BFRCAST(const char *, ef->file + private_shdrtab(ef)[ef->ehdr->e_shstrndx].sh_offset); }

const struct bfelf_rela *
private_relatab(
    struct bfelf_file_t *ef)
{ return BFRCAST(const struct bfelf_rela *, ef->exec + ef->rela_array_addr); }

/* -------------------------------------------------------------------------- */
/* ELF Implementation (File Valid)                                            */
/* -------------------------------------------------------------------------- */

/*
 * Notes:
 * - Once the init function is run, the file and ehdr variables in the ef
 *   struct are valid. Once the load function is complete, these variables
 *   are zero'd out and they are no longer valid. If you make mods, make sure
 *   you pay attention to this. The relocate function must be able to execute
 *   without direct access to the ELF file.
 * - Do not attempt to store pointers unless you plan to zero them out after
 *   the load function. We assume that some of the functions are called by
 *   a "loader" and others are called by the "runtime". It is possible that
 *   these are the same thing, but this is not always the case. Sometimes, the
 *   runtime is actually the ELF file itself, and its address space is likely
 *   not the same as the loader. Instead, store offsets so that the runtime
 *   can make sense of the information and calculate its own pointers when it
 *   performs a relocation.
 */

static inline status_t
bfelf_file_init(const void *file, struct bfelf_file_t *ef)
{
    bfelf64_half i;
    const struct bfelf_phdr *first = nullptr;

    if (file == nullptr) {
        BFALERT("file == nullptr\n");
        return BFFAILURE;
    }

    if (ef == nullptr) {
        BFALERT("ef == nullptr\n");
        return BFFAILURE;
    }

    private_memset(ef, 0, sizeof(struct bfelf_file_t));

    ef->file = BFSCAST(const uint8_t *, file);
    ef->ehdr = BFRCAST(const struct bfelf_ehdr *, file);

    if (ef->ehdr->e_ident[bfei_mag0] != 0x7F) {
        BFALERT("magic #0 has unexpected value\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_ident[bfei_mag1] != 'E') {
        BFALERT("magic #1 has unexpected value\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_ident[bfei_mag2] != 'L') {
        BFALERT("magic #2 has unexpected value\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_ident[bfei_mag3] != 'F') {
        BFALERT("magic #3 has unexpected value\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_ident[bfei_class] != bfelfclass64) {
        BFALERT("file is not 64bit\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_ident[bfei_data] != bfelfdata2lsb) {
        BFALERT("file is not little endian\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_ident[bfei_version] != bfev_current) {
        BFALERT("unsupported version\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_ident[bfei_osabi] != bfelfosabi_sysv) {
        BFALERT("file does not use the system v abi\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_ident[bfei_abiversion] != 0) {
        BFALERT("unsupported abi version\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_machine != bfem_x86_64) {
        BFALERT("file must be compiled for x86_64 or bfem_aarch64\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_version != bfev_current) {
        BFALERT("unsupported version\n");
        return BFFAILURE;
    }

    if (ef->ehdr->e_flags != 0) {
        BFALERT("unsupported flags\n");
        return BFFAILURE;
    }

    for (i = 0; i < ef->ehdr->e_phnum; i++) {
        const struct bfelf_phdr *phdr = &(private_phdrtab(ef)[i]);

        if (phdr->p_type != bfpt_load) {
            continue;
        }

        if (first == nullptr) {
            first = phdr;
        }

        ef->size = phdr->p_paddr - first->p_paddr + phdr->p_memsz;
    }

    return BFSUCCESS;
}

static inline status_t
bfelf_file_load(
    struct bfelf_file_t *ef,
    void *exec,
    status_t (*mark_rx_func)(void *, size_t))
{
    bfelf64_half i;
    const struct bfelf_phdr *first = nullptr;

    if (ef == nullptr) {
        BFALERT("ef == nullptr\n");
        return BFFAILURE;
    }

    if (ef->size == 0) {
        BFALERT("ef->size == 0\n");
        return BFFAILURE;
    }

    if (exec == nullptr) {
        BFALERT("exec == nullptr\n");
        return BFFAILURE;
    }

    ef->exec = BFSCAST(uint8_t *, exec);
    private_memset(ef->exec, 0, ef->size);

    for (i = 0; i < ef->ehdr->e_phnum; i++) {
        uint8_t *dst;
        const uint8_t *src;
        const struct bfelf_phdr *phdr = &(private_phdrtab(ef)[i]);

        if (phdr->p_type != bfpt_load) {
            continue;
        }

        if (first == nullptr) {
            first = phdr;
        }

        src = ef->file + phdr->p_offset;
        dst = ef->exec + (phdr->p_paddr - first->p_paddr);
        private_memcpy(dst, src, phdr->p_filesz);

        switch(phdr->p_flags) {
            case bfpf_rx:
                if (mark_rx_func != nullptr) {
                    if (mark_rx_func(dst, phdr->p_memsz) != BFSUCCESS) {
                        return BFFAILURE;
                    }
                }

                break;

            case bfpf_rw:
                break;

            default:
                BFALERT("ELF segments other than RW or RE are not supported\n");
                return BFFAILURE;
        };
    }

    for (i = 0; i < ef->ehdr->e_shnum; i++) {
        const struct bfelf_shdr *shdr = &(private_shdrtab(ef)[i]);
        const char *name = &(private_shstrtab(ef)[shdr->sh_name]);

        if (private_strcmp(name, ".rela.dyn") == BFSUCCESS) {
            ef->rela_array_addr = shdr->sh_addr;
            ef->rela_array_size = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".init_array") == BFSUCCESS) {
            ef->init_array_addr = shdr->sh_addr;
            ef->init_array_size = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".fini_array") == BFSUCCESS) {
            ef->fini_array_addr = shdr->sh_addr;
            ef->fini_array_size = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".eh_frame") == BFSUCCESS) {
            ef->eh_frame_addr = shdr->sh_addr;
            ef->eh_frame_size = shdr->sh_size;
            continue;
        }

        if (private_strcmp(name, ".init") == BFSUCCESS) {
            BFALERT("ELF file has unsupported section: init\n");
            return BFFAILURE;
        }

        if (private_strcmp(name, ".fini") == BFSUCCESS) {
            BFALERT("ELF file has unsupported section: fini\n");
            return BFFAILURE;
        }

        if (private_strcmp(name, ".ctors") == BFSUCCESS) {
            BFALERT("ELF file has unsupported section: ctors\n");
            return BFFAILURE;
        }

        if (private_strcmp(name, ".dtors") == BFSUCCESS) {
            BFALERT("ELF file has unsupported section: dtors\n");
            return BFFAILURE;
        }
    }

    ef->entry = ef->ehdr->e_entry;

    ef->file = nullptr;
    ef->ehdr = nullptr;

    return BFSUCCESS;
}

static inline status_t
bfelf_file_relocate(
    struct bfelf_file_t *ef,
    bfelf64_addr virt)
{
    bfelf64_half i;
    const struct bfelf_rela *rela_table;

    if (ef == nullptr) {
        BFALERT("ef == nullptr\n");
        return BFFAILURE;
    }

    if (ef->rela_array_addr == 0) {
        BFALERT("ELF file is not relocatable\n");
        return BFFAILURE;
    }

    if (virt == 0 && ef->exec == nullptr) {
        BFALERT("btoh virt and exec == nullptr\n");
        return BFFAILURE;
    }

    if (virt == 0) {
        virt = BFRCAST(bfelf64_addr, ef->exec);
    }

    if (ef->exec == nullptr) {
        ef->exec = BFRCAST(uint8_t *, virt);
    }

    for (i = 0; i < ef->rela_array_size / sizeof(struct bfelf_rela); i++) {
        const struct bfelf_rela *rela = &(private_relatab(ef)[i]);

        switch (BFELF_REL_TYPE(rela->r_info)) {
            case BFR_X86_64_RELATIVE: {
                bfelf64_addr *addr =
                    BFRCAST(bfelf64_addr *, ef->exec + rela->r_offset);

                *addr += virt;
                break;
            }

            default:
                BFALERT("unsupported relocation type\n");
                return BFFAILURE;
        }
    }

    if (ef->init_array_addr != 0) {
        ef->init_array_addr += virt;
    }

    if (ef->fini_array_addr != 0) {
        ef->fini_array_addr += virt;
    }

    if (ef->eh_frame_addr != 0) {
        ef->eh_frame_addr += virt;
    }

    ef->entry += virt;

    return BFSUCCESS;
}

#ifdef __cplusplus
}
#endif

#pragma pack(pop)

#endif
