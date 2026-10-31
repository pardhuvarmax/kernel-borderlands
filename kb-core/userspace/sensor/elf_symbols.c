// SPDX-License-Identifier: GPL-2.0
#include "elf_symbols.h"

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Map a virtual address to a file offset through an executable PT_LOAD.
static int vaddr_to_file_offset(const Elf64_Phdr *ph, int n, Elf64_Addr vaddr, size_t *out)
{
    for (int i = 0; i < n; i++) {
        if (ph[i].p_type != PT_LOAD || !(ph[i].p_flags & PF_X))
            continue;
        if (vaddr >= ph[i].p_vaddr && vaddr < ph[i].p_vaddr + ph[i].p_filesz) {
            *out = (size_t)(vaddr - ph[i].p_vaddr + ph[i].p_offset);
            return 1;
        }
    }
    return 0;
}

size_t kb_elf_function_file_offset(const char *elf_path, const char *symbol_name)
{
    size_t result = 0;
    Elf64_Shdr *shdrs = NULL;
    Elf64_Phdr *phdrs = NULL;
    Elf64_Sym *syms = NULL;
    char *strs = NULL;

    FILE *f = fopen(elf_path, "rb");
    if (!f)
        return 0;

    Elf64_Ehdr eh;
    if (fread(&eh, 1, sizeof(eh), f) != sizeof(eh) ||
        memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_shentsize != sizeof(Elf64_Shdr) || eh.e_phentsize != sizeof(Elf64_Phdr) ||
        eh.e_shnum == 0 || eh.e_phnum == 0)
        goto out;

    phdrs = malloc(sizeof(Elf64_Phdr) * eh.e_phnum);
    shdrs = malloc(sizeof(Elf64_Shdr) * eh.e_shnum);
    if (!phdrs || !shdrs)
        goto out;
    if (fseek(f, (long)eh.e_phoff, SEEK_SET) != 0 || fread(phdrs, sizeof(Elf64_Phdr), eh.e_phnum, f) != eh.e_phnum)
        goto out;
    if (fseek(f, (long)eh.e_shoff, SEEK_SET) != 0 || fread(shdrs, sizeof(Elf64_Shdr), eh.e_shnum, f) != eh.e_shnum)
        goto out;

    // Prefer the full symbol table (Go binaries, unstripped programs); shared
    // libraries usually only have the dynamic one.
    const Elf64_Shdr *symtab = NULL;
    for (int i = 0; i < eh.e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) { symtab = &shdrs[i]; break; }
        if (shdrs[i].sh_type == SHT_DYNSYM && !symtab) symtab = &shdrs[i];
    }
    if (!symtab || symtab->sh_entsize != sizeof(Elf64_Sym) || symtab->sh_link >= eh.e_shnum)
        goto out;
    const Elf64_Shdr *strtab = &shdrs[symtab->sh_link];

    syms = malloc(symtab->sh_size);
    strs = malloc(strtab->sh_size + 1);
    if (!syms || !strs)
        goto out;
    if (fseek(f, (long)symtab->sh_offset, SEEK_SET) != 0 || fread(syms, 1, symtab->sh_size, f) != symtab->sh_size ||
        fseek(f, (long)strtab->sh_offset, SEEK_SET) != 0 || fread(strs, 1, strtab->sh_size, f) != strtab->sh_size)
        goto out;
    strs[strtab->sh_size] = '\0';

    size_t n = symtab->sh_size / sizeof(Elf64_Sym);
    for (size_t i = 0; i < n; i++) {
        if (syms[i].st_name >= strtab->sh_size || strcmp(strs + syms[i].st_name, symbol_name) != 0)
            continue;
        if (ELF64_ST_TYPE(syms[i].st_info) != STT_FUNC || syms[i].st_shndx == SHN_UNDEF || syms[i].st_value == 0)
            continue;   // a data symbol or an import is not a probe target
        size_t off;
        if (vaddr_to_file_offset(phdrs, eh.e_phnum, syms[i].st_value, &off))
            result = off;
        break;
    }

out:
    free(syms);
    free(strs);
    free(shdrs);
    free(phdrs);
    fclose(f);
    return result;
}
