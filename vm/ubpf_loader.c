// Copyright (c) 2015 Big Switch Networks, Inc
// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright 2015 Big Switch Networks, Inc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <ubpf_config.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include "ubpf_int.h"

#if defined(UBPF_HAS_ELF_H)
#include <elf.h>
#endif

#define MAX_SECTIONS 32

#ifndef EM_BPF
#define EM_BPF 247
#endif

#ifndef R_BPF_64_64
#define R_BPF_64_64 1
#endif

#ifndef R_BPF_64_32
#define R_BPF_64_32 2
#endif

#if defined(UBPF_HAS_ELF_H)

struct bounds
{
    const void* base;
    uint64_t size;
};

struct section
{
    const Elf64_Shdr* shdr;
    const void* data;
    uint64_t size;
};

static const void*
bounds_check(struct bounds* bounds, uint64_t offset, uint64_t size)
{
    if (offset + size > bounds->size || offset + size < offset) {
        return NULL;
    }
    return bounds->base + offset;
}

int
ubpf_load_elf(struct ubpf_vm* vm, const void* elf, size_t elf_size, char** errmsg)
{
    struct bounds b = {.base = elf, .size = elf_size};
    void* text_copy = NULL;
    int i;

    const Elf64_Ehdr* ehdr = bounds_check(&b, 0, sizeof(*ehdr));
    if (!ehdr) {
        *errmsg = ubpf_error("not enough data for ELF header");
        goto error;
    }

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG)) {
        *errmsg = ubpf_error("wrong magic");
        goto error;
    }

    if (ehdr->e_ident[EI_CLASS] != ELFCLASS64) {
        *errmsg = ubpf_error("wrong class");
        goto error;
    }

    if (ehdr->e_ident[EI_DATA] != ELFDATA2LSB) {
        *errmsg = ubpf_error("wrong byte order");
        goto error;
    }

    if (ehdr->e_ident[EI_VERSION] != 1) {
        *errmsg = ubpf_error("wrong version");
        goto error;
    }

    if (ehdr->e_ident[EI_OSABI] != ELFOSABI_NONE) {
        *errmsg = ubpf_error("wrong OS ABI");
        goto error;
    }

    if (ehdr->e_type != ET_REL) {
        *errmsg = ubpf_error("wrong type, expected relocatable");
        goto error;
    }

    if (ehdr->e_machine != EM_NONE && ehdr->e_machine != EM_BPF) {
        *errmsg = ubpf_error("wrong machine, expected none or BPF, got %d", ehdr->e_machine);
        goto error;
    }

    if (ehdr->e_shnum > MAX_SECTIONS) {
        *errmsg = ubpf_error("too many sections");
        goto error;
    }

    /* Parse section headers into an array */
    struct section sections[MAX_SECTIONS];
    uint64_t shoff = ehdr->e_shoff;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr* shdr = bounds_check(&b, shoff, sizeof(*shdr));
        shoff += ehdr->e_shentsize;
        if (!shdr) {
            *errmsg = ubpf_error("bad section header offset or size");
            goto error;
        }

        const void* data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
        if (!data) {
            *errmsg = ubpf_error("bad section offset or size");
            goto error;
        }

        sections[i].shdr = shdr;
        sections[i].data = data;
        sections[i].size = shdr->sh_size;
    }

    /* Find first text section */
    int text_shndx = 0;
    for (i = 0; i < ehdr->e_shnum; i++) {
        const Elf64_Shdr* shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS && shdr->sh_flags == (SHF_ALLOC | SHF_EXECINSTR)) {
            text_shndx = i;
            break;
        }
    }

    if (!text_shndx) {
        *errmsg = ubpf_error("text section not found");
        goto error;
    }

    struct section* text = &sections[text_shndx];

    /* May need to modify text for relocations, so make a copy */
    text_copy = malloc(text->size);
    if (!text_copy) {
        *errmsg = ubpf_error("failed to allocate memory");
        goto error;
    }
    memcpy(text_copy, text->data, text->size);

    /* Process each relocation section */
    for (i = 0; i < ehdr->e_shnum; i++) {
        struct section* rel = &sections[i];
        if (rel->shdr->sh_type != SHT_REL) {
            continue;
        } else if (rel->shdr->sh_info != text_shndx) {
            continue;
        }

        const Elf64_Rel* rs = rel->data;

        if (rel->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ubpf_error("bad symbol table section index");
            goto error;
        }

        struct section* symtab = &sections[rel->shdr->sh_link];
        const Elf64_Sym* syms = symtab->data;
        uint32_t num_syms = symtab->size / sizeof(syms[0]);

        if (symtab->shdr->sh_link >= ehdr->e_shnum) {
            *errmsg = ubpf_error("bad string table section index");
            goto error;
        }

        struct section* strtab = &sections[symtab->shdr->sh_link];
        const char* strings = strtab->data;

        int j;
        for (j = 0; j < rel->size / sizeof(Elf64_Rel); j++) {
            /* Copy rs[j] as it may not be appropriately aligned */
            Elf64_Rel r;
            memcpy(&r, rs + j, sizeof(Elf64_Rel));

            uint32_t sym_idx = ELF64_R_SYM(r.r_info);
            if (sym_idx >= num_syms) {
                *errmsg = ubpf_error("bad symbol index");
                goto error;
            }

            /* Copy syms[sym_idx] as it may not be appropriately aligned */
            Elf64_Sym sym;
            memcpy(&sym, syms + sym_idx, sizeof(Elf64_Sym));

            if (sym.st_name >= strtab->size) {
                *errmsg = ubpf_error("bad symbol name");
                goto error;
            }

            const char* sym_name = strings + sym.st_name;

            if (r.r_offset + 8 > text->size) {
                *errmsg = ubpf_error("bad relocation offset");
                goto error;
            }

            switch (ELF64_R_TYPE(r.r_info)) {
            // Perform map relocation.
            case R_BPF_64_64: {
                if (sym.st_shndx > ehdr->e_shnum) {
                    *errmsg = ubpf_error("bad section index");
                    goto error;
                }
                struct section* map = &sections[sym.st_shndx];
                if (map->shdr->sh_type != SHT_PROGBITS || map->shdr->sh_flags != (SHF_ALLOC | SHF_WRITE)) {
                    *errmsg = ubpf_error("bad map section");
                    goto error;
                }

                if (sym.st_size + sym.st_value > map->size) {
                    *errmsg = ubpf_error("bad map size");
                    goto error;
                }

                struct ebpf_inst* inst = (struct ebpf_inst*)(text_copy + r.r_offset);
                struct ebpf_inst* inst2 = (struct ebpf_inst*)(text_copy + r.r_offset + sizeof(struct ebpf_inst));
                if (inst->opcode != EBPF_OP_LDDW) {
                    *errmsg = ubpf_error("bad relocation instruction");
                    goto error;
                }
                if (r.r_offset + sizeof(struct ebpf_inst) * 2 > text->size) {
                    *errmsg = ubpf_error("bad relocation offset");
                    goto error;
                }

                if (!vm->data_relocation_function) {
                    *errmsg = ubpf_error("map relocation function not set");
                    goto error;
                }

                const uint8_t* data = sym.st_value + map->data;
                uint64_t size = sym.st_size;
                uint64_t imm =
                    vm->data_relocation_function(vm->data_relocation_user_data, data, size, sym_name, sym.st_value);
                inst->imm = (uint32_t)imm;
                inst2->imm = (uint32_t)(imm >> 32);
                break;
            }
            // Perform function relocation.
            // Note: This is a uBPF specific relocation type and is not part of the ELF specification.
            // It is used to perform resolution from helper function name to helper function id.
            case R_BPF_64_32: {
                unsigned int imm = ubpf_lookup_registered_function(vm, sym_name);
                if (imm == -1) {
                    *errmsg = ubpf_error("function '%s' not found", sym_name);
                    goto error;
                }

                *(uint32_t*)(text_copy + r.r_offset + 4) = imm;
                break;
            }
            default:
                *errmsg = ubpf_error("bad relocation type %u", ELF64_R_TYPE(r.r_info));
                goto error;
                break;
            }
        }
    }

    int rv = ubpf_load(vm, text_copy, sections[text_shndx].size, errmsg);
    free(text_copy);
    return rv;

error:
    free(text_copy);
    return -1;
}
#endif
