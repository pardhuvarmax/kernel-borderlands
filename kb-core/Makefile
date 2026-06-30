# KB Core Makefile — All 6 Hooks
OUTPUT     := .output
BUILD      := build
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

BINARIES := $(addprefix $(BUILD)/,$(HOOKS))

.PHONY: all clean vmlinux

all: $(BINARIES)

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

$(BUILD):
	@mkdir -p $(BUILD)

# Each binary links against libbpf
# kb_memory and kb_network need no extra libs
# kb_syscall needs -lm for math

$(BUILD)/kb_process: userspace/kb_process.c $(OUTPUT)/kb_process.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

$(BUILD)/kb_syscall: userspace/kb_syscall.c $(OUTPUT)/kb_syscall.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -lm -o $@

$(BUILD)/kb_privilege: userspace/kb_privilege.c $(OUTPUT)/kb_privilege.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

$(BUILD)/kb_file: userspace/kb_file.c $(OUTPUT)/kb_file.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

$(BUILD)/kb_network: userspace/kb_network.c $(OUTPUT)/kb_network.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

$(BUILD)/kb_memory: userspace/kb_memory.c $(OUTPUT)/kb_memory.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

# Add near the bottom, before clean:

$(BUILD)/kbd_sensor: userspace/kbd_sensor.c $(OUTPUT)/kbd_sensor.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

kbd_sensor: $(BUILD)/kbd_sensor

# ── Convenience targets (build/run by short name) ──────────
kb_process: $(BUILD)/kb_process
kb_syscall: $(BUILD)/kb_syscall
kb_privilege: $(BUILD)/kb_privilege
kb_file: $(BUILD)/kb_file
kb_network: $(BUILD)/kb_network
kb_memory: $(BUILD)/kb_memory

# ── Clean ───────────────────────────────────────────────────
clean:
	rm -rf $(OUTPUT) $(BUILD)