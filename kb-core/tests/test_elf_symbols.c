// SPDX-License-Identifier: GPL-2.0
// Regression test for the uprobe offset bug: the sensor passed a symbol's
// VIRTUAL ADDRESS to bpf_program__attach_uprobe(), which needs a FILE OFFSET.
// For a static non-PIE executable (how Go builds tailscaled) they differ by
// 0x400000, so the breakpoint landed 4 MB away inside unrelated code and the
// probed process crashed in a restart loop, which froze the VM.
//
// Run from kb-core/ (needs gcc, nm, readelf; no root, no kernel):
//   gcc -O2 -Wall -I userspace/sensor -o /tmp/test_elf_symbols tests/test_elf_symbols.c userspace/sensor/elf_symbols.c && /tmp/test_elf_symbols

#include <elf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "elf_symbols.h"

#define CHECK(cond, msg) do { if (!(cond)) { printf("FAIL: %s (line %d)\n", msg, __LINE__); exit(1); } } while (0)

static unsigned long long sh_text_addr, sh_text_off;

static unsigned long long nm_addr(const char *bin, const char *sym)
{
    char cmd[512], line[256];
    snprintf(cmd, sizeof cmd, "nm %s | grep ' [Tt] %s$'", bin, sym);
    FILE *p = popen(cmd, "r");
    unsigned long long a = 0;
    if (p && fgets(line, sizeof line, p))
        a = strtoull(line, NULL, 16);
    if (p) pclose(p);
    return a;
}

static void read_text_section(const char *bin)
{
    char cmd[512], line[512];
    snprintf(cmd, sizeof cmd, "readelf -SW %s | grep -E ' \\.text '", bin);
    FILE *p = popen(cmd, "r");
    sh_text_addr = sh_text_off = 0;
    if (p && fgets(line, sizeof line, p)) {
        char *t = strstr(line, "PROGBITS");
        if (t) sscanf(t, "PROGBITS %llx %llx", &sh_text_addr, &sh_text_off);
    }
    if (p) pclose(p);
}

static void build(const char *flags, const char *out)
{
    FILE *f = fopen("/tmp/kb_fixture.c", "w");
    fputs("int kb_fixture_data = 7;\n"
          "__attribute__((noinline)) int kb_fixture_probe_target(int x) { return x * 3 + 1; }\n"
          "int main(int c, char **v) { (void)v; return kb_fixture_probe_target(c) + kb_fixture_data; }\n", f);
    fclose(f);
    char cmd[512];
    snprintf(cmd, sizeof cmd, "gcc -O0 %s -o %s /tmp/kb_fixture.c 2>/dev/null", flags, out);
    CHECK(system(cmd) == 0, "fixture failed to build");
}

static void test_static_non_pie_translates_vaddr_to_file_offset(void)
{
    build("-static -no-pie", "/tmp/kb_fixture_static");
    unsigned long long vaddr = nm_addr("/tmp/kb_fixture_static", "kb_fixture_probe_target");
    read_text_section("/tmp/kb_fixture_static");
    CHECK(vaddr != 0 && sh_text_addr != 0, "could not read the fixture's symbol/section");
    unsigned long long expected = vaddr - sh_text_addr + sh_text_off;
    CHECK(sh_text_addr - sh_text_off == 0x400000, "fixture does not have the tailscaled-style 0x400000 split");
    size_t got = kb_elf_function_file_offset("/tmp/kb_fixture_static", "kb_fixture_probe_target");
    printf("(vaddr 0x%llx -> file offset 0x%zx, expected 0x%llx) ", vaddr, got, expected);
    CHECK(got == expected, "offset must be the FILE offset");
    CHECK(got != vaddr, "returning the virtual address is the original bug");
}

static void test_pie_matches_the_section_math_too(void)
{
    build("-pie -fPIE", "/tmp/kb_fixture_pie");
    unsigned long long vaddr = nm_addr("/tmp/kb_fixture_pie", "kb_fixture_probe_target");
    read_text_section("/tmp/kb_fixture_pie");
    size_t got = kb_elf_function_file_offset("/tmp/kb_fixture_pie", "kb_fixture_probe_target");
    CHECK(got == vaddr - sh_text_addr + sh_text_off, "PIE offset must also equal vaddr - .text addr + .text offset");
}

static void test_refuses_to_guess(void)
{
    CHECK(kb_elf_function_file_offset("/tmp/kb_fixture_static", "no_such_symbol") == 0, "missing symbol must give 0");
    CHECK(kb_elf_function_file_offset("/tmp/kb_fixture_static", "kb_fixture_data") == 0, "a data symbol is not a probe target");
    CHECK(kb_elf_function_file_offset("/etc/hostname", "x") == 0, "a non-ELF file must give 0");
    CHECK(kb_elf_function_file_offset("/nonexistent/binary", "x") == 0, "a missing file must give 0");
}

#define RUN(t) do { printf("Running " #t "... "); t(); printf("PASS\n"); } while (0)
int main(void)
{
    RUN(test_static_non_pie_translates_vaddr_to_file_offset);
    RUN(test_pie_matches_the_section_math_too);
    RUN(test_refuses_to_guess);
    printf("All ELF symbol tests passed\n");
    return 0;
}
