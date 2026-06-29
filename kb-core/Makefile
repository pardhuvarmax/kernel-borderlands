# KB Core Makefile — All 6 Hooks
OUTPUT     := .output
BPFTOOL    := $(shell which bpftool)
CLANG      := clang
ARCH       := $(shell uname -m | \
               sed 's/x86_64/x86/' | \
               sed 's/aarch64/arm64/')
LIBBPF     := ../libbpf/src/libbpf.a
INCLUDES   := -I$(OUTPUT) -I../libbpf/include/uapi -Iinclude
CFLAGS     := -g -Wall $(INCLUDES)
BPF_CFLAGS := -g -O2 -target bpf \
               -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

HOOKS := kb_process kb_syscall kb_privilege \
         kb_file kb_network kb_memory

.PHONY: all clean vmlinux

all: $(HOOKS)

# ── vmlinux.h ──────────────────────────────────────────────
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux \
		format c > include/vmlinux.h

# ── Generic rules for all hooks ────────────────────────────

$(OUTPUT)/%.bpf.o: ebpf/%.bpf.c include/vmlinux.h
	@mkdir -p $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

# Each binary links against libbpf
# kb_memory and kb_network need no extra libs
# kb_syscall needs -lm for math

kb_process: userspace/kb_process.c $(OUTPUT)/kb_process.skel.h
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

kb_syscall: userspace/kb_syscall.c $(OUTPUT)/kb_syscall.skel.h
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -lm -o $@

kb_privilege: userspace/kb_privilege.c $(OUTPUT)/kb_privilege.skel.h
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

kb_file: userspace/kb_file.c $(OUTPUT)/kb_file.skel.h
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

kb_network: userspace/kb_network.c $(OUTPUT)/kb_network.skel.h
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

kb_memory: userspace/kb_memory.c $(OUTPUT)/kb_memory.skel.h
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

# ── Clean ───────────────────────────────────────────────────
clean:
	rm -rf $(OUTPUT) $(HOOKS)