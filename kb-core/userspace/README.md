# Userspace Loaders

C programs that load, attach, and read from eBPF programs.
These bridge the kernel eBPF layer and the Go control plane.

## Programs
- `kb_process.c`   — Loader for process lifecycle eBPF
- `kb_syscall.c`   — Loader for syscall tracker
- `kb_privilege.c` — Loader for privilege monitor
- `kb_file.c`      — Loader for file access monitor
- `kb_network.c`   — Loader for network monitor
- `kb_memory.c`    — Loader for memory monitor

## Notes
- Each loader reads from perf ring buffer
- Forwards events to Control Plane via Unix socket / gRPC
- Uses libbpf skeleton API
