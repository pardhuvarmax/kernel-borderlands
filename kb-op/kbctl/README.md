# kbctl — Control Plane CLI Client (`kb-op/kbctl/`)

`kbctl` is the command-line control utility for Kernel Borderlands. Built on Go, Cobra, and gRPC, it exposes the complete Control Plane management API directly to the shell, enabling scripted incident response playbooks, CI pipeline automation, and manual operator overrides.

---

## 1. Subsystem Architecture

```mermaid
flowchart LR
    Operator([Security Operator]) -->|kbctl command| CLI[kbctl Client]
    CLI -->|gRPC over UDS /run/kb/kba.sock| Gateway(gRPC Gateway)
    Gateway --> ControlPlane[Go Control Plane Daemon]
```

`kbctl` communicates directly with the `kb-control-plane` daemon over structured protocol buffer payloads on kbd's existing gRPC Unix domain socket (`/run/kb/kba.sock`) — the same socket every other RPC client (`kb-mcp`, `kb-tui`) uses; gRPC multiplexes every method of the `KernelBorderlands` service over that one connection, so no separate port or socket is needed. Every execution request is verified, authorized, and logged to the tamper-evident audit ledger.

---

## 2. Command Reference

### A. Policy Management
Reload policy configurations dynamically without restarting loaded eBPF programs or active userspace daemons:
```bash
# Reload YAML policy files and re-evaluate active processes
kbctl policy reload
```

### B. Threat Zone & Enforcement Overrides
Manually adjust process threat classifications or isolate specific compromised processes:
```bash
# Relabel how kbd tracks a process's zone (display/classification only —
# does not touch kernel/enforcement state; a real zone transition from the
# sensor will overwrite it the next time the process's score crosses a
# threshold). Audit-logged.
kbctl zone override --pid 1234 --zone SUSPICIOUS

# Forcefully contain/isolate a process via kbd's SetContainment RPC.
# Defaults to NAMESPACE; pass --level to choose CGROUP, SECCOMP, or TERMINATE.
kbctl process isolate --pid 1234
kbctl process isolate --pid 1234 --level TERMINATE
```

### C. System Metrics & Audit Log Verification/Export
Verify or export the SHA-256 chained audit ledger, or query general statistics:
```bash
# Verify the audit log's hash chain has not been tampered with
kbctl audit verify

# Export the full SHA-256 chained audit log in JSON format
kbctl audit export --out /var/log/kb_audit.json

# Fetch global telemetry volumes and active process counts
kbctl stats
```

---

## 3. Build & Run

### Compiling from Source
```bash
# Navigate to kbctl directory
cd kb-op/kbctl

# Compile the CLI binary
go build -o kbctl .
```

### Configuration Flags
By default, `kbctl` connects to kbd's gRPC Unix domain socket at `/run/kb/kba.sock`. Use `--socket` to point at a different path (e.g. a non-default `KB_GRPC_SOCKET` the daemon was started with):
```bash
kbctl policy reload --socket /run/kb/kba.sock
```

## Owner
- Rupa — CLI Tooling and Operator Infra.