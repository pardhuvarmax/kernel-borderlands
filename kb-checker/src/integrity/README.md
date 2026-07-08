# eBPF Integrity & Liveness Audits (`kb-checker/src/integrity/`)

This module implements low-level kernel validation audits to detect BPF-level compromises, hook bypasses, and map state tampering.

---

## 📂 Verification Functions

### 1. `verify_ebpf_integrity()`
* **Mechanism**: Iterates over loaded BPF programs using `bpf_prog_get_next_id`, extracts the JITed xlated instructions from kernel memory via `bpf_obj_get_info_by_fd`, and verifies their SHA-256 signatures against `/etc/kb/ebpf_policies.json`.
* **Action on Failure**: Unloads the C sensor and triggers core subsystem halting.

### 2. `verify_liveness()`
* **Mechanism**: Establishes a subscription to the Go daemon's `StreamEvents` gRPC API, forks a transient test process (`/bin/true`), and verifies that the `sched_process_exec` telemetry event streams back within 3 seconds.
* **Action on Failure**: Unloads the C sensor and halts the core subsystem.

### 3. `verify_map_integrity()`
* **Mechanism**: Traverses loaded BPF maps system-wide to locate `contained_pids_map`. Dumps its active keys and compares them with the quarantined process database from Go.
* **Self-Healing**: If a quarantined PID is missing or has a modified containment level in kernel space, it automatically re-enforces the value using `bpf_map_update_elem`.
