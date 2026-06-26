# KB Core Makefile
OUTPUT    := .output
BUILD  	  := build
BPFTOOL   := $(shell which bpftool)
CLANG     := clang
ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
LIBBPF    := ../libbpf/src/libbpf.a
INCLUDES  := -I$(OUTPUT) -I../libbpf/include/uapi -Iinclude
CFLAGS    := -g -Wall $(INCLUDES)
BPF_CFLAGS := -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

.PHONY: all clean vmlinux

all: kb_process kb_syscall

# ── vmlinux.h ──────────────────────────────────────
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux \
		format c > include/vmlinux.h

# ── Hook 1: Process Lifecycle ───────────────────────
$(OUTPUT)/kb_process.bpf.o: ebpf/kb_process.bpf.c include/vmlinux.h
	@mkdir -p $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)/kb_process.skel.h: $(OUTPUT)/kb_process.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

kb_process: userspace/kb_process.c $(OUTPUT)/kb_process.skel.h
	@mkdir -p $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $(BUILD)/$@

# ── Hook 2: Syscall Entropy ─────────────────────────
$(OUTPUT)/kb_syscall.bpf.o: ebpf/kb_syscall.bpf.c include/vmlinux.h
	@mkdir -p $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)/kb_syscall.skel.h: $(OUTPUT)/kb_syscall.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

kb_syscall: userspace/kb_syscall.c $(OUTPUT)/kb_syscall.skel.h
	@mkdir -p $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -lm -o $(BUILD)/$@

# ── Clean ───────────────────────────────────────────
clean:
	rm -rf $(OUTPUT) $(BUILD)