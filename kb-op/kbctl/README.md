# kbctl — Control Plane CLI Client (`kb-op/kbctl/`)

`kbctl` is the command-line control utility for Kernel Borderlands. Built on Go, Cobra, and gRPC, it exposes the complete Control Plane management API directly to the shell, enabling scripted incident response playbooks, CI pipeline automation, and manual operator overrides.

---

## 1. Subsystem Architecture

```mermaid
flowchart LR
    Operator([Security Operator]) -->|kbctl command| CLI[kbctl Client]
    CLI -->|gRPC / Port 50051| Gateway(gRPC Gateway)
    Gateway --> ControlPlane[Go Control Plane Daemon]
```

`kbctl` communicates directly with the `kb-control-plane` daemon over structured protocol buffer payloads. Every execution request is verified, authorized, and logged to the tamper-evident audit ledger.

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
# Manually override a process threat classification zone
kbctl zone override --pid 1234 --zone SUSPICIOUS

# Forcefully isolate/quarantine a process (triggers BPF LSM access denial)
kbctl process isolate --pid 1234
```

### C. System Metrics & Audit Log Exports
Export cryptographic audit ledgers or query general statistics:
```bash
# Export the full SHA-256 chained audit logs in JSON format
kbctl audit export --out /var/log/kb_audit.json

# Fetch global telemetry volumes and active eBPF mapping statistics
kbctl stats
```

---

## 3. Build & Run

### Compiling from Source
```bash
# Navigate to kbctl directory
cd kb-op/kbctl

# Compile the CLI binary
go build -o kbctl main.go
```

### Configuration Flags
By default, `kbctl` connects to `localhost:50051`. You can configure the target endpoint using flags:
```bash
# Specify a different gRPC server endpoint
kbctl policy reload --server 192.168.1.100:50051
```

## Owner
- Rupa — CLI Tooling and Operator Infra.