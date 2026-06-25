# KB Core Makefile
OUTPUT := .output
LIBBPF_SRC := $(abspath ../libbpf/src)
BPFTOOL := $(shell which bpftool)

CLANG := clang
ARCH := x86

CFLAGS := -g -Wall -I$(OUTPUT) -I../libbpf/include/uapi

.PHONY: all clean

all: $(OUTPUT) kb_process

$(OUTPUT):
	mkdir -p $(OUTPUT)

$(OUTPUT)/kb_process.bpf.o: ebpf/kb_process.bpf.c include/vmlinux.h
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) \
		-I include \
		-I ../libbpf/include/uapi \
		-c $< -o $@

$(OUTPUT)/kb_process.skel.h: $(OUTPUT)/kb_process.bpf.o
	$(BPFTOOL) gen skeleton $< > $@

kb_process: userspace/kb_process.c $(OUTPUT)/kb_process.skel.h
	$(CLANG) $(CFLAGS) $< \
		../libbpf/src/libbpf.a \
		-lelf -lz -o $@

clean:
	rm -rf $(OUTPUT) kb_process

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h