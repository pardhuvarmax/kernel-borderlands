# Headers

- `vmlinux.h`     — Auto-generated kernel type definitions (BTF)
- `kb_common.h`   — Shared structs between eBPF and userspace
- `kb_events.h`   — Event type definitions

## Generate vmlinux.h
```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```
