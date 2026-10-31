// SPDX-License-Identifier: GPL-2.0
#ifndef KB_ELF_SYMBOLS_H
#define KB_ELF_SYMBOLS_H

#include <stddef.h>

// File offset of a FUNCTION symbol in an ELF64 file, which is what
// bpf_program__attach_uprobe() needs, or 0 if the symbol is missing, is not a
// function, or does not lie inside an executable PT_LOAD segment.
//
// A symbol's st_value is a VIRTUAL ADDRESS. For PIE and most shared objects the
// first loadable segment has p_vaddr == p_offset, so the two coincide, but for
// static non-PIE executables, which is how Go builds tailscaled, text is mapped at
// 0x400000, so the virtual address is 0x400000 larger than the file offset. The
// sensor used st_value directly: it planted its uprobe breakpoint 4 MB away
// from the intended function, in the middle of unrelated code, and the probed
// process crashed (tailscaled, in a restart loop). This translates through the
// program headers, and returns 0 (do not attach) rather than guessing.
size_t kb_elf_function_file_offset(const char *elf_path, const char *symbol_name);

#endif
