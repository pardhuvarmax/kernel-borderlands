# KB Core Makefile — All 6 Hooks

OUTPUT     := .output
BUILD      := build

COLLECTORS := userspace/collectors
SENSOR      := userspace/sensor
BEHAVIOR    := userspace/behavior
BRIDGE      := userspace/bridge

BPFTOOL    := $(shell which bpftool)
CLANG      := clang

ARCH       := $(shell uname -m | \
               sed 's/x86_64/x86/' | \
               sed 's/aarch64/arm64/')

LIBBPF     := ../libbpf/src/libbpf.a

INCLUDES := \
    -I$(OUTPUT) \
    -Iinclude \
    -I$(BRIDGE) \
    -I../libbpf/include/uapi
CFLAGS     := -g -Wall $(INCLUDES)
BPF_CFLAGS := -g -O2 -target bpf \
              -D__TARGET_ARCH_$(ARCH) $(INCLUDES)

HOOKS := kb_process kb_syscall kb_privilege \
         kb_file kb_network kb_memory \
         kbd_sensor

BINARIES := $(addprefix $(BUILD)/,$(HOOKS))

.PHONY: all clean vmlinux

all: $(BINARIES)

# ────────────────────────────────────────────────────────────
# Generate vmlinux.h
# ────────────────────────────────────────────────────────────

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux \
		format c > include/vmlinux.h

# ────────────────────────────────────────────────────────────
# Generic eBPF Rules
# ────────────────────────────────────────────────────────────

$(OUTPUT)/%.bpf.o: ebpf/%.bpf.c include/vmlinux.h
	@mkdir -p $(OUTPUT)
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

$(OUTPUT)/%.skel.h: $(OUTPUT)/%.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

$(BUILD):
	@mkdir -p $(BUILD)

# ────────────────────────────────────────────────────────────
# Userspace Collectors
# ────────────────────────────────────────────────────────────

$(BUILD)/kb_process: $(COLLECTORS)/kb_process.c $(OUTPUT)/kb_process.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

$(BUILD)/kb_syscall: $(COLLECTORS)/kb_syscall.c $(OUTPUT)/kb_syscall.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -lm -o $@

$(BUILD)/kb_privilege: $(COLLECTORS)/kb_privilege.c $(OUTPUT)/kb_privilege.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

$(BUILD)/kb_file: $(COLLECTORS)/kb_file.c $(OUTPUT)/kb_file.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

$(BUILD)/kb_network: $(COLLECTORS)/kb_network.c $(OUTPUT)/kb_network.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

$(BUILD)/kb_memory: $(COLLECTORS)/kb_memory.c $(OUTPUT)/kb_memory.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $< $(LIBBPF) -lelf -lz -o $@

# ────────────────────────────────────────────────────────────
# Unified Sensor
# ────────────────────────────────────────────────────────────

SENSOR_SRCS := \
    $(SENSOR)/kbd_sensor.c \
    $(BEHAVIOR)/kb_scoring.c \
    $(BEHAVIOR)/kb_evidence.c \
    $(BEHAVIOR)/kb_behavior.c \
    $(BEHAVIOR)/kb_rules.c \
    $(BRIDGE)/kb_bridge.c

$(BUILD)/kbd_sensor: $(SENSOR_SRCS) $(OUTPUT)/kbd_sensor.skel.h | $(BUILD)
	$(CLANG) $(CFLAGS) $(SENSOR_SRCS) \
	    $(LIBBPF) -lelf -lz -lm -o $@

# ────────────────────────────────────────────────────────────
# Convenience Targets
# ────────────────────────────────────────────────────────────

kb_process:    $(BUILD)/kb_process
kb_syscall:    $(BUILD)/kb_syscall
kb_privilege:  $(BUILD)/kb_privilege
kb_file:       $(BUILD)/kb_file
kb_network:    $(BUILD)/kb_network
kb_memory:     $(BUILD)/kb_memory
kbd_sensor:    $(BUILD)/kbd_sensor

# ────────────────────────────────────────────────────────────
# Clean
# ────────────────────────────────────────────────────────────

clean:
	rm -rf $(OUTPUT) $(BUILD)