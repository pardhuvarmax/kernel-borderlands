# KB Core — eBPF Instrumentation Layer

The kernel-level observability layer for Kernel Borderlands.
Implements all 6 hook points via eBPF CO-RE programs.

## Structure
- `ebpf/`      — eBPF C programs (kernel side)
- `userspace/` — Userspace loaders (C)
- `include/`   — vmlinux.h and shared headers
- `scripts/`   — Build and test scripts
- `tests/`     — Unit and integration tests

## Hook Points
- `tracepoint:syscalls` — All syscall entry/exit
- `tracepoint:sched`    — Fork, exec, exit events
- `kprobe:commit_creds` — Privilege changes
- `bpf_lsm`            — File access (LSM hooks)
- `tracepoint:net`      — Network activity
- `kprobe:mmap_region`  — Memory mapping

## Build
```bash
make vmlinux
make
sudo ./kb_process
```

## Owner
- Pardhu Varma — Systems & Security
- Karthik — Systems Integration & Subsystem Testing (Collab)
