# KB Core — eBPF Instrumentation & Security Layer

The kernel-level observability and security enforcement layer for Kernel Borderlands. Implements dynamic system tracing, out-of-band TLS inspection, and in-kernel security containment using eBPF CO-RE (Compile Once – Run Everywhere) and BPF LSM.

---

## Subsystem Architecture

### 1. Directory Structure
*   **`ebpf/`**: Core eBPF C programs running in Ring 0 (kernel-space).
    -   `kbd_sensor.bpf.c`: Consolidated eBPF sensor implementing execution tracking, privilege changes, file accesses, memory violations, and uprobes.
*   **`userspace/`**: Userspace loader and bridge client written in C.
    -   `sensor/kbd_sensor.c`: Main loader daemon. Manages maps, processes ELF symbols, dynamically attaches uprobes, and forwards events to the IPC bridge.
    -   `bridge/kb_bridge.c`: Low-level IPC bridge client using Unix domain sockets.
*   **`include/`**: Struct mappings and shared C headers.
*   **`tests/`**: Unit tests for scoring/behavior and mock hook integration triggers.

---

## eBPF Telemetry & Containment Hooks

### A. Containment-Triggered VFS LSM File Blocking (BPF LSM)
*   **Hook**: `lsm/file_open`
*   **Description**: Intercepts file open operations at the Virtual File System (VFS) layer after symlinks and relative directories are resolved.
*   **Verdict**: For a process already under operator containment at level ≥2 (Seccomp or above), queries the dynamic `kb_sensitive_paths` eBPF map and returns `-EACCES` (-13) to natively block open attempts inside kernel-space before they return to userland. Uncontained processes are never blocked — sensitive-path reads are always flagged for behavioral scoring regardless of containment state, but the hard block is targeted at already-contained processes, not blanket, so it doesn't interfere with routine operation (`sudo`, PAM, etc. reading `/etc/sudoers`/`/etc/shadow`).
*   **Verifier-Safe Directory Traversal**: Resolves parent directories dynamically using an unrolled loop (`#pragma unroll`) to perform suffix checks without exceeding BPF verifier complexity limits.

### B. Out-of-Band Plaintext TLS Inspection
Using userspace uprobes, KB intercepts decrypted payloads directly in memory before encryption or after decryption, supporting:
*   **OpenSSL (`libssl.so`)**: Hooks `SSL_write`. Collects parameters using the System V ABI (receiver in `RDI`, buffer in `RSI`, length in `RDX`).
*   **GnuTLS (`libgnutls.so`)**: Hooks `gnutls_record_send` (System V ABI).
*   **NSS (`libnss3.so`)**: Hooks NSPR socket `PR_Write` (System V ABI).
*   **Go Runtime (`crypto/tls`)**: Dynamic offset parsing in `/proc/[pid]/exe`. Reads slices using Go `ABIInternal` register conventions (`RBX` for backing array address, `RCX` for length).

### C. In-Context Hijacking Protection
*   **`/proc/*/mem` Protection**: The path auditor detects and flags file access queries attempting to read/write process memory spaces via procfs.
*   **Cross-Process Memory Injection**: Hooks `sys_enter_process_vm_writev` system call to intercept shellcode injection between distinct PIDs.
*   **Sensitive Capability Probing**: Hooks `kprobe/security_capable` to audit capability requests (such as `CAP_SYS_ADMIN`, `CAP_SYS_PTRACE`, `CAP_SYS_RAWIO`, and `CAP_DAC_OVERRIDE`) by non-root users.

---

## Build and Run

### Prerequisites
*   Clang/LLVM, bpftool, libelf, libz.
*   BPF LSM support enabled in grub (`lsm=...,bpf`).

### Recompilation
To perform a clean rebuild of the entire C sensor, dynamic skeletons, and shared loaders:
```bash
make clean && make
```

### Execution
Run the sensor as superuser to load eBPF hooks into the kernel:
```bash
sudo ./build/kbd_sensor
```

---

## Contributors & Subsystem Owners
*   **Pardhu Varma** — Lead Kernel & Security Subsystems Engineer (`kb-core` Lead)
*   **Karthik** — Systems Integration & Test Simulation (Collaboration)
