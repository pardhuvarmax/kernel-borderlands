# eBPF Programs (Kernel Side)

All eBPF C programs that run inside Ring 0 (kernel-space), compiled with clang using CO-RE (Compile Once – Run Everywhere) and verified by the kernel's eBPF verifier.

---

## Program Layout

### 1. Consolidated Sensor (`kbd_sensor.bpf.c`)
To minimize context switching and shared map lookup overheads, the core observability suite has been unified into a single, high-efficiency sensor program:
*   **Tracepoints**:
    -   `sched_process_exec` / `sched_process_exit`: Process lifecycle events.
    -   `sys_enter_process_vm_writev`: Intercepts cross-process virtual memory writes (inject attacks).
    -   `sys_enter_openat`: Captures file access events.
*   **Kprobes**:
    -   `kprobe/commit_creds`: Triggers on process privilege credential escalations.
    -   `kprobe/security_capable`: Audits capability checks by non-root users (like `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`).
*   **Uprobes**:
    -   `kb_ssl_write`: Hook for OpenSSL, GnuTLS, and NSS plaintext transmission.
    -   `kb_go_tls_write`: Hook for statically compiled Go runtimes.
*   **LSM (BPF LSM)**:
    -   `kb_lsm_file_open`: Intercepts file open operations at the VFS layer and applies dynamic prefix block decisions.

---

## eBPF Maps & State Structures
*   **`kb_events`** (`BPF_MAP_TYPE_RINGBUF`): Single 1MB unified ring buffer for userspace event streaming.
*   **`kb_sensitive_paths`** (`BPF_MAP_TYPE_HASH`): Dynamic map holding prefixes of files/directories to audit and block.
*   **`kb_syscall_counts`** & **`kb_syscall_totals`**: Track per-PID system call distributions for sliding-window entropy analysis.
*   **`kb_cred_prev`**: Stores process credential snapshots to identify privilege drift.

---

## Design and Verifier Rules
1.  **Verifier Compliance**: All loops must be fully unrolled using `#pragma unroll` and bounded by fixed sizes to satisfy static verifier analysis.
2.  **No Floating Point**: Kernel space does not support floats. All statistics must be computed in userspace.
3.  **CO-RE / BTF**: Must use `vmlinux.h` generated from active system BTF schemas.
