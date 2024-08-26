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

#include "ebpf.h"
#include <sys/types.h>
#include <ubpf_config.h>

#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>
#include "ubpf_int.h"


#include <ctype.h>
#include <linux/btf.h>

#if defined(UBPF_HAS_ELF_H)
#if defined(UBPF_HAS_ELF_H_COMPAT)
#include <libelf.h>
#else
#include <elf.h>
#endif
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

typedef struct _bounds
{
    const void* base;
    uint64_t size;
} bounds;

typedef struct _section
{
    const Elf64_Shdr* shdr;
    const void* data;
    uint64_t size;
} section;

struct relocated_function
{
    const char* name;
    const Elf64_Shdr* shdr;
    const void* native_data;
    const void* linked_data;
    uint64_t native_section_start;
    Elf64_Xword size;
    uint64_t landed;
};

static const void*
bounds_check(bounds* bounds, uint64_t offset, uint64_t size)
{
    if (offset + size > bounds->size || offset + size < offset) {
        return NULL;
    }
    return bounds->base + offset;
}

const int MAIN_SECTION_INDEX = 0;
const int TEXT_SECTION_INDEX = 1;

int
section_idx_from_name(const char** section_names, int length, const char* needle)
{
    for (int i = 0; i < length; i++) {
        if (!strcmp(section_names[i], needle)) {
            return i;
        }
    }
    return -1;
}

// static const char *__btf_kind_str(__u16 kind)
// {
// 	switch (kind) {
// 	case BTF_KIND_UNKN: return "void";
// 	case BTF_KIND_INT: return "int";
// 	case BTF_KIND_PTR: return "ptr";
// 	case BTF_KIND_ARRAY: return "array";
// 	case BTF_KIND_STRUCT: return "struct";
// 	case BTF_KIND_UNION: return "union";
// 	case BTF_KIND_ENUM: return "enum";
// 	case BTF_KIND_FWD: return "fwd";
// 	case BTF_KIND_TYPEDEF: return "typedef";
// 	case BTF_KIND_VOLATILE: return "volatile";
// 	case BTF_KIND_CONST: return "const";
// 	case BTF_KIND_RESTRICT: return "restrict";
// 	case BTF_KIND_FUNC: return "func";
// 	case BTF_KIND_FUNC_PROTO: return "func_proto";
// 	case BTF_KIND_VAR: return "var";
// 	case BTF_KIND_DATASEC: return "datasec";
// 	case BTF_KIND_FLOAT: return "float";
// 	case BTF_KIND_DECL_TAG: return "decl_tag";
// 	case BTF_KIND_TYPE_TAG: return "type_tag";
// 	case BTF_KIND_ENUM64: return "enum64";
// 	default: return "unknown";
// 	}
// }

struct btf_type * ubpf_btf_get_type_by_idx_slow(struct btf_header *hdr, size_t idx) {
    struct btf_type *type = (struct btf_type *)((char *)(hdr + 1) + hdr->type_off);
    size_t type_offset = 0;

    /* btf type for "void" */
    if (!idx)
        return NULL;

    int i = 1;
    for (; type_offset < hdr->type_len;) {
        if (i == idx) {
            return type;
        }

        if (BTF_INFO_KIND(type->info) == BTF_KIND_INT) {
            type_offset += sizeof(uint32_t);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_ARRAY) {
            type_offset += sizeof(struct btf_array);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_STRUCT || BTF_INFO_KIND(type->info) == BTF_KIND_UNION) {
            type_offset += sizeof(struct btf_member) * BTF_INFO_VLEN(type->info);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_ENUM) {
            type_offset += sizeof(struct btf_enum) * BTF_INFO_VLEN(type->info);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_FUNC_PROTO) {
            type_offset += sizeof(struct btf_param) * BTF_INFO_VLEN(type->info);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_VAR) {
            type_offset += sizeof(struct btf_var);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_DATASEC) {
            type_offset += sizeof(struct btf_var_secinfo) * BTF_INFO_VLEN(type->info);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_DECL_TAG) {
            type_offset += sizeof(struct btf_decl_tag);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_ENUM64) {
            type_offset += sizeof(struct btf_enum64) * BTF_INFO_VLEN(type->info);
        }

        type_offset += sizeof(struct btf_type);
        type = (struct btf_type *)(type_offset + (char *)(hdr + 1) + hdr->type_off);
        ++i;
    }

    return NULL;
}

static inline bool ubpf_btf_type_is_mod(const struct btf_type *t)
{
	uint16_t kind = BTF_INFO_KIND(t->info);

	return kind == BTF_KIND_VOLATILE ||
	       kind == BTF_KIND_CONST ||
	       kind == BTF_KIND_RESTRICT ||
	       kind == BTF_KIND_TYPE_TAG ||
           kind == BTF_KIND_TYPEDEF ||
           kind == BTF_KIND_PTR;
}

struct btf_type *
ubpf_btf_get_type_by_idx_without_mods_slow(struct btf_header *hdr, size_t idx)
{
	struct btf_type *t = ubpf_btf_get_type_by_idx_slow(hdr, idx);

	for (;ubpf_btf_type_is_mod(t);) {
		t = ubpf_btf_get_type_by_idx_slow(hdr, t->type);
	}

	return t;
}

static inline int ubpf_btf_get_map_member_value_from_array_size(struct btf_header *btf_hdr, struct btf_member *m) {
    struct btf_type *t = ubpf_btf_get_type_by_idx_without_mods_slow(btf_hdr, m->type);
    struct btf_array *arr = (struct btf_array *)(t + 1);

    if (BTF_INFO_KIND(t->info) != BTF_KIND_ARRAY)
        return -1;

    return arr->nelems;
}

static int ubpf_parse_btf_map_desc_from_var(struct btf_header *btf_hdr, struct btf_type *type, struct ubpf_btf_map_desc *map)
{
    struct btf_type *map_desc_type = NULL;
    const char *strs = (char *)(btf_hdr + 1) + btf_hdr->str_off;
    int i = 0;

    if (BTF_INFO_KIND(type->info) != BTF_KIND_VAR)
        return -1;

    map_desc_type = ubpf_btf_get_type_by_idx_slow(btf_hdr, type->type);

    if (BTF_INFO_KIND(map_desc_type->info) != BTF_KIND_STRUCT)
        return -2;

    map->name = strs + type->name_off;
    for(; i < BTF_INFO_VLEN(map_desc_type->info); ++i) {
        struct btf_member *m = (struct btf_member *)(map_desc_type + 1) + i;
        if (!strncmp("type", strs + m->name_off, 4)) {
            int val = ubpf_btf_get_map_member_value_from_array_size(btf_hdr, m);
            map->type = val;
        } else if (!strncmp("key_size", strs + m->name_off, 8)) {
            int val = ubpf_btf_get_map_member_value_from_array_size(btf_hdr, m);
            map->key_size = val;
        } else if (!strncmp("value_size", strs + m->name_off, 10)) {
            int val = ubpf_btf_get_map_member_value_from_array_size(btf_hdr, m);
            map->value_size = val;
        } else if (!strncmp("max_entries", strs + m->name_off, 11)) {
            int val = ubpf_btf_get_map_member_value_from_array_size(btf_hdr, m);
            map->max_entries = val;
        } else if (!strncmp("map_flags", strs + m->name_off, 9)) {
            int val = ubpf_btf_get_map_member_value_from_array_size(btf_hdr, m);
            map->map_flags = val;
        }
    }

    return 0;
}

static int ubpf_parse_btf(struct ubpf_vm* vm, const Elf64_Shdr* btf_section, const char* btf_data, int btf_size, char** errmsg)
{
    struct btf_header *btf_hdr = (struct btf_header *)btf_data;
    (void)btf_section;
    (void)btf_size;
    const char *strs = (char *)(btf_hdr + 1) + btf_hdr->str_off;
    struct btf_type *type = (struct btf_type *)((char *)(btf_hdr + 1) + btf_hdr->type_off);
    size_t type_offset = 0;
    int i = 1;
    for (; type_offset < btf_hdr->type_len;) {
        ++i;

        if (BTF_INFO_KIND(type->info) == BTF_KIND_INT) {
            type_offset += sizeof(uint32_t);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_ARRAY) {
            type_offset += sizeof(struct btf_array);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_STRUCT || BTF_INFO_KIND(type->info) == BTF_KIND_UNION) {
            type_offset += sizeof(struct btf_member) * BTF_INFO_VLEN(type->info);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_ENUM) {
            type_offset += sizeof(struct btf_enum) * BTF_INFO_VLEN(type->info);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_FUNC_PROTO) {
            type_offset += sizeof(struct btf_param) * BTF_INFO_VLEN(type->info);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_VAR) {
            type_offset += sizeof(struct btf_var);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_DATASEC) {
            type_offset += sizeof(struct btf_var_secinfo) * BTF_INFO_VLEN(type->info);

            /* Parse bpf map descriptions */
            if (!strncmp(".maps", strs + type->name_off, 5)) {
                vm->btf_maps_cnt = BTF_INFO_VLEN(type->info);
                vm->btf_maps = calloc(vm->btf_maps_cnt, sizeof(struct ubpf_btf_map_desc));
                if (!vm->btf_maps) {
                    *errmsg = ubpf_error("could not allocate memory for storing information about BPF maps");
                    return -1;
                }
                int j = 0;
                for (; j < BTF_INFO_VLEN(type->info); ++j) {
                    struct btf_var_secinfo* sec = (struct btf_var_secinfo*)(type + 1) + j;
                    struct btf_type* var = ubpf_btf_get_type_by_idx_slow(btf_hdr, sec->type);
                    ubpf_parse_btf_map_desc_from_var(btf_hdr, var, &vm->btf_maps[j]);
                }
            }
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_DECL_TAG) {
            type_offset += sizeof(struct btf_decl_tag);
        } else if (BTF_INFO_KIND(type->info) == BTF_KIND_ENUM64) {
            type_offset += sizeof(struct btf_enum64) * BTF_INFO_VLEN(type->info);
        }

        type_offset += sizeof(struct btf_type);
        type = (struct btf_type *)(type_offset + (char *)(btf_hdr + 1) + btf_hdr->type_off);
    }

    return 0;
}

int
ubpf_load_elf_ex(struct ubpf_vm* vm, const void* elf, size_t elf_size, const char* main_function_name, char** errmsg)
{
    bounds b = {.base = elf, .size = elf_size};
    void* linked_program = NULL;
    int section_count = -1;
    int i;
    uint total_functions = 0;
    int load_success = -1;
    struct relocated_function** relocated_functions = NULL;

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

    section_count = ehdr->e_shnum;

    /* Parse section headers into an array */
    section sections[MAX_SECTIONS];
    uint64_t current_section_header_offset = ehdr->e_shoff;
    for (i = 0; i < section_count; i++) {
        const Elf64_Shdr* shdr = bounds_check(&b, current_section_header_offset, sizeof(Elf64_Ehdr*));
        if (!shdr) {
            *errmsg = ubpf_error("bad section header offset or size");
            goto error;
        }
        current_section_header_offset += ehdr->e_shentsize;

        const void* data = bounds_check(&b, shdr->sh_offset, shdr->sh_size);
        if (!data) {
            *errmsg = ubpf_error("bad section offset or size");
            goto error;
        }

        sections[i].shdr = shdr;
        sections[i].data = data;
        sections[i].size = shdr->sh_size;
    }

    const char* strtab_data = NULL;
    int strtab_size = 0;
    for (i = 0; i < section_count; i++) {
        const Elf64_Shdr* shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_STRTAB) {
            strtab_data = sections[i].data;
            strtab_size = sections[i].size;
            break;
        }
    }

    if (!strtab_data) {
        *errmsg = ubpf_error("could not find the string table in the elf file");
        goto error;
    }

    Elf64_Sym* symbols = NULL;
    int symtab_size = 0;
    for (i = 0; i < section_count; i++) {
        const Elf64_Shdr* shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_SYMTAB) {
            symbols = (Elf64_Sym*)sections[i].data;
            symtab_size = sections[i].size;
            break;
        }
    }

    if (!symbols) {
        *errmsg = ubpf_error("could not find the symbol table in the elf file");
        goto error;
    }

    uint64_t total_symbols = symtab_size / sizeof(Elf64_Sym);
    uint linked_program_size = 0;

    /*
     * Be conservative and assume that each of the symbols represents a function.
     */
    relocated_functions = (struct relocated_function**)calloc(total_symbols, sizeof(struct relocated_function*));

    if (relocated_functions == NULL) {
        *errmsg = ubpf_error("could not allocate memory for storing information about relocated functions");
        goto error;
    }

    total_functions = 1;
    for (uint64_t i = 0; i < total_symbols; i++) {
        const Elf64_Sym* sym = symbols + i;

        if (ELF64_ST_TYPE(sym->st_info) != STT_FUNC) {
            continue;
        }

        /*
         * Until that we are sure the symbol is valid, we use a stack-allocated relocated_function.
         */
        struct relocated_function rf = {};

        if (sym->st_name >= strtab_size) {
            *errmsg = ubpf_error("a function symbol contained a bad name");
            goto error;
        }
        rf.name = strtab_data + sym->st_name;

        if (sym->st_shndx > section_count) {
            *errmsg = ubpf_error("a function symbol contained a bad section index");
            goto error;
        }
        rf.shdr = sections[sym->st_shndx].shdr;

        if (rf.shdr->sh_type != SHT_PROGBITS || rf.shdr->sh_flags != (SHF_ALLOC | SHF_EXECINSTR)) {
            *errmsg = ubpf_error("function symbol %s points to a non-executable section", sym->st_name);
            goto error;
        }

        rf.native_data = sections[sym->st_shndx].data + sym->st_value;

        rf.size = sym->st_size;
        rf.native_section_start = sym->st_value;

        linked_program_size += rf.size;

        bool is_main_function = (main_function_name && !strcmp(rf.name, main_function_name));
        /*
         * When the user did not give us a main function, we assume that the function at the beginning
         * of the .text section is the main function.
         */
        bool is_default_main_function =
            (!main_function_name && !strcmp(strtab_data + rf.shdr->sh_name, ".text") && rf.native_section_start == 0);

        struct relocated_function* rfp = NULL;
        if (is_main_function || is_default_main_function) {
            rfp = relocated_functions[0] = (struct relocated_function*)calloc(1, sizeof(struct relocated_function));
        } else {
            rfp = relocated_functions[total_functions++] =
                (struct relocated_function*)calloc(1, sizeof(struct relocated_function));
        }
        if (rfp == NULL) {
            *errmsg = ubpf_error("could not allocate space to store metadata about a relocated function");
            goto error;
        }
        memcpy(rfp, &rf, sizeof(struct relocated_function));
    }

    if (!relocated_functions[0]) {
        *errmsg = ubpf_error("%s function not found.", main_function_name);
        goto error;
    }

    linked_program = (char*)calloc(linked_program_size, sizeof(char));
    if (!linked_program) {
        *errmsg = ubpf_error("failed to allocate memory for the linked program");
        goto error;
    }

    uint64_t current_landing_spot = 0;
    for (uint i = 0; i < total_functions; i++) {
        memcpy(
            linked_program + current_landing_spot, relocated_functions[i]->native_data, relocated_functions[i]->size);
        relocated_functions[i]->landed = current_landing_spot / 8;
        relocated_functions[i]->linked_data = linked_program + current_landing_spot;
        current_landing_spot += relocated_functions[i]->size;
    }

    const Elf64_Shdr* btf_section = NULL;
    const char* btf_data = NULL;
    int btf_size = 0;
    for (i = 0; i < section_count; i++) {
        const Elf64_Shdr* shdr = sections[i].shdr;
        if (shdr->sh_type == SHT_PROGBITS && !strncmp(".BTF", strtab_data + shdr->sh_name, 5)) {
            btf_section = shdr;
            btf_data = sections[i].data;
            btf_size = sections[i].size;
            break;
        }
    }

    ubpf_parse_btf(vm, btf_section, btf_data, btf_size, errmsg);

    /* Process each relocation section */
    for (i = 0; i < section_count; i++) {

        section* relo_section = &sections[i];
        if (relo_section->shdr->sh_type != SHT_REL) {
            continue;
        }

        /* the sh_info field is the index of the section to which these relocations apply. */
        int relo_applies_to_section = relo_section->shdr->sh_info;
        int relo_symtab_idx = relo_section->shdr->sh_link;

        /* Right now the loader only handles relocations that are applied to an executable section. */
        if (sections[relo_applies_to_section].shdr->sh_type != SHT_PROGBITS ||
            sections[relo_applies_to_section].shdr->sh_flags != (SHF_ALLOC | SHF_EXECINSTR)) {
            continue;
        }
        const Elf64_Rel* rs = relo_section->data;

        if (relo_symtab_idx >= section_count) {
            *errmsg = ubpf_error("bad symbol table section index");
            goto error;
        }

        section* relo_symtab = &sections[relo_symtab_idx];
        const Elf64_Sym* relo_syms = relo_symtab->data;
        uint32_t relo_symtab_num_syms = relo_symtab->size / sizeof(relo_syms[0]);

        int j;
        for (j = 0; j < relo_section->size / sizeof(Elf64_Rel); j++) {
            /* Copy rs[j] as it may not be appropriately aligned */
            Elf64_Rel relocation;
            memcpy(&relocation, rs + j, sizeof(Elf64_Rel));

            if (ELF64_R_SYM(relocation.r_info) >= relo_symtab_num_syms) {
                *errmsg = ubpf_error("a relocation contained a bad symbol index");
                goto error;
            }

            /* No matter what the relocation type, the 4 MSBs are an index to a symbol
             * in the symbol table. So, we will set that up here for everyone's use.
             */
            Elf64_Sym relo_sym;
            memcpy(&relo_sym, relo_syms + ELF64_R_SYM(relocation.r_info), sizeof(Elf64_Sym));
            if (relo_sym.st_name >= strtab_size) {
                *errmsg = ubpf_error("a relocation's symbol contained a bad name");
                goto error;
            }
            const char* relo_sym_name = strtab_data + relo_sym.st_name;
            /*
             * Let each relocation type handle the semantics of that symbol
             * table entry on its own.
             */

            struct relocated_function* source_function = NULL;

            for (uint i = 0; i < total_functions; i++) {
                if (sections[relo_applies_to_section].shdr == relocated_functions[i]->shdr &&
                    relocation.r_offset > relocated_functions[i]->native_section_start &&
                    relocation.r_offset < relocated_functions[i]->native_section_start + relocated_functions[i]->size) {
                    source_function = relocated_functions[i];
                    break;
                }
            }

            if (!source_function) {
                *errmsg = ubpf_error("a relocation's symbol contained a bad name");
                goto error;
            }

            struct ebpf_inst* applies_to_inst =
                (struct
                 ebpf_inst*)(source_function->linked_data + (relocation.r_offset - source_function->native_section_start));
            uint64_t applies_to_inst_index =
                source_function->landed + ((relocation.r_offset - source_function->native_section_start) / 8);

            if (!source_function) {
                *errmsg = ubpf_error("an instruction with relocation is not in a function");
                goto error;
            }

            switch (ELF64_R_TYPE(relocation.r_info)) {
            case R_BPF_64_64: {
                if (relocation.r_offset + 8 > sections[relo_applies_to_section].size) {
                    *errmsg = ubpf_error("bad R_BPF_64_64 relocation offset");
                    goto error;
                }

                if (relo_sym.st_shndx > section_count) {
                    *errmsg = ubpf_error("bad R_BPF_64_64 relocation section index");
                    goto error;
                }
                section* map = &sections[relo_sym.st_shndx];
                // if (map->shdr->sh_type != SHT_PROGBITS || map->shdr->sh_flags != (SHF_ALLOC | SHF_WRITE)) {
                //     *errmsg = ubpf_error("bad R_BPF_64_64 relocation section");
                //     goto error;
                // }

                if (relo_sym.st_size + relo_sym.st_value > map->size) {
                    *errmsg = ubpf_error("bad R_BPF_64_64 size");
                    goto error;
                }

                struct ebpf_inst* applies_to_inst2 = applies_to_inst + 1;
                if (applies_to_inst->opcode != EBPF_OP_LDDW) {
                    *errmsg = ubpf_error("bad R_BPF_64_64 relocation instruction");
                    goto error;
                }
                if (relocation.r_offset + sizeof(struct ebpf_inst) * 2 > sections[relo_applies_to_section].size) {
                    *errmsg = ubpf_error("bad R_BPF_64_64 relocation offset");
                    goto error;
                }

                if (!vm->data_relocation_function) {
                    *errmsg = ubpf_error("R_BPF_64_64 data relocation function not set");
                    goto error;
                }

                struct ubpf_btf_map_desc *btf_map = NULL;
                for (uint i = 0; i < vm->btf_maps_cnt; i++) {
                    if (!strcmp(vm->btf_maps[i].name, relo_sym_name)) {
                        btf_map = &vm->btf_maps[i];
                        break;
                    }
                }

                uint64_t imm = vm->data_relocation_function(
                    vm->data_relocation_user_data,
                    /* TODO: change this hack or remove btf completely */
                    btf_map ? btf_map : map->data,
                    map->size,
                    relo_sym_name,
                    relo_sym.st_value,
                    relo_sym.st_size);
                applies_to_inst->imm = (uint32_t)imm;
                applies_to_inst2->imm = (uint32_t)(imm >> 32);
                break;
            }
            case R_BPF_64_32: {
                if (applies_to_inst->src == 1) {
                    // Perform local function call relocation.
                    int target_function_in_section_idx = relo_sym.st_shndx;

                    uint offset_in_target_section = (applies_to_inst->imm + 1) * 8;

                    struct relocated_function* target_function = NULL;
                    for (uint i = 0; i < total_functions; i++) {
                        if (sections[target_function_in_section_idx].shdr == relocated_functions[i]->shdr &&
                            offset_in_target_section == relocated_functions[i]->native_section_start) {
                            target_function = relocated_functions[i];
                            break;
                        }
                    }
                    if (!target_function) {
                        *errmsg = ubpf_error("relocated target of a function call does not point to a known function");
                        goto error;
                    }

                    applies_to_inst->imm = target_function->landed - (applies_to_inst_index + 1);
                } else {
                    // Perform helper function relocation.
                    // Note: This is a uBPF specific relocation type and is not part of the ELF specification.
                    // It is used to perform resolution from helper function name to helper function id.
                    const char* section_name = strtab_data + relo_sym.st_name;
                    unsigned int imm = ubpf_lookup_registered_function(vm, section_name);
                    if (imm == -1) {
                        *errmsg = ubpf_error("function '%s' not found", section_name);
                        goto error;
                    }

                    applies_to_inst->imm = imm;
                }
                break;
            }
            default:
                printf(
                    "Warning: bad relocation type %llu; skipping.\n",
                    (long long unsigned)ELF64_R_TYPE(relocation.r_info));
                break;
            }
        }
    }

    /*
     * We got this far -- we'll set a provisional success value.
     */
    load_success = 1;

error:
    for (uint i = 0; i < total_functions; i++) {
        if (relocated_functions[i] != NULL) {
            free(relocated_functions[i]);
        }
    }
    free(relocated_functions);

    if (load_success > 0) {
        load_success = ubpf_load(vm, linked_program, linked_program_size, errmsg);
    }
    free(linked_program);
    return load_success;
}

int
ubpf_load_elf(struct ubpf_vm* vm, const void* elf, size_t elf_size, char** errmsg)
{
    return ubpf_load_elf_ex(vm, elf, elf_size, NULL, errmsg);
}

#endif
