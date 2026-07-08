# KB Checker — Safety & Integrity Watchdog
> **Design Philosophy**: Keep It Simple, Stupid (KISS). Complexity is the enemy of security.

`kb-checker` is the independent safety watchdog for the Kernel Borderlands platform. Built in safe, system-level Rust, it is designed with a minimal code footprint, zero persistent state, and zero network exposure to ensure it remains trusted, auditable, and resilient.

---

## 💡 KISS Design Pillars

To guarantee the highest level of security and prevent the safety layer itself from being compromised, `kb-checker` is implemented under four simplicity rules:

1. **Zero Runtime State**: The checker is completely stateless. It does not write databases, log files, or maintain process memory history. Every iteration is a fresh query of system truth (kernel memory & local sockets).
2. **Operating System Delegation**: We do not reinvent the wheel. Rather than writing complex process managers or custom firewall engines, the checker delegates execution to standard Linux utilities:
   * **`systemctl`** for service reloading and detaching BPF objects.
   * **POSIX `flock`** for atomic single-instance execution guards.
   * **`iptables`** for host network quarantine isolation.
3. **No Network Footprint**: The watchdog exposes no TCP/UDP ports. All communication is UDS-only (`kba.sock`, `kbc.sock`).
4. **Hardened Dependency Chaining**: By separating safety logic from telemetry scoring (`kbd`) and agent networks (`kb-aads`), the watchdog cannot be crashed or bypassed by application-level vulnerabilities.

---

## 📂 Directory Structure

*   **`src/`** — Rust safety validation logic.
    *   [`src/integrity/`](src/integrity/README.md) — eBPF JIT signature audits, hook liveness, and self-healing maps.
    *   [`src/service_check/`](src/service_check/README.md) — gRPC health connection loops and Ray swarm REST audits.
    *   [`src/report/`](src/report/README.md) — Systemd service recovery and 3-layer quarantine containment.
    *   [`src/grpc/`](src/grpc/README.md) — Diagnostic status server (listening on UDS `/run/kb/kbc.sock`).
*   **[`proto/`](proto/README.md)** — gRPC schema contracts for status reporting and control plane check endpoints.
*   **[`event_sets/`](event_sets/README.md)** — JSON threat simulation scenario sets used by the sandbox tester.
*   **`tests/`** — UDS health checking integration test suite.

---

## ⚙️ Enforcement & Containment Flow

```
[System Boot]
      │
      ▼
[1. JIT Signature Audit] ── (Mismatch) ──► [Emergency Halting]
      │ (Pass)                                     │
      ▼                                            ▼
[2. BPF Map Self-Heal]   ── (Tampering) ─► [systemctl stop kb-sensor]
      │ (Pass)                                     │
      ▼                                            ▼ (Stop Fails)
[3. Heartbeat Liveness]  ── (Bypass) ────► [1. SIGKILL Userspace]
      │ (Pass)                                     │
      ▼                                            ▼ (Kill Fails)
[Release systemd gate]                     [2. Detach bpftool links]
      │                                            │
      ▼                                            ▼ (Detach Fails)
[Start Ray/AADS Swarm]                     [3. iptables Network Drop]
```

---

## 🚀 Execution & Command Guide

### Compile the Binary
```bash
cargo build --release
```

### Start the Watchdog Daemon
Starts all validation loops in the background (Default: JIT signatures check, Map audits, UDS health checks, Liveness Heartbeats, and Latency monitoring):
```bash
./target/release/kb-checker monitor --all
```

### Run One-off Integrity Diagnostics
```bash
# Verify active eBPF bytecode signatures
./target/release/kb-checker check ebpf

# Audit eBPF map quarantine consistency and self-heal mismatches
./target/release/kb-checker check map

# Run an active end-to-end telemetry liveness heartbeat test
./target/release/kb-checker check liveness

# Audit eBPF hook latency overheads
./target/release/kb-checker check performance
```

---

## 👥 Subsystem Owners
*   **Pardhu Varma** — Lead Architect, Systems & Kernel Integrity (`kb-checker` Owner)
*   **Tejaswini** — Defensive Pipeline Integration (Collaboration)
