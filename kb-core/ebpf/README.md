# eBPF Programs (Kernel Side)

All eBPF C programs that run inside the kernel.
Written in C, compiled with clang, verified by the kernel's eBPF verifier.

## Programs
- `kb_process.bpf.c`   — Process lifecycle (exec/exit/fork)
- `kb_syscall.bpf.c`   — Syscall entropy tracking
- `kb_privilege.bpf.c` — Privilege escalation detection
- `kb_file.bpf.c`      — Sensitive file access (LSM)
- `kb_network.bpf.c`   — Network behavior tracking
- `kb_memory.bpf.c`    — Memory mapping anomalies

## Rules
- All programs must be CO-RE compatible (BTF required)
- Use BPF_MAP_TYPE_RINGBUF for event emission
- Minimal work in kernel — emit and return
- No loops unless bounded
