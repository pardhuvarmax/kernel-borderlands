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

### D. CWP Protected-Workload Registry
Reload `workloads.yaml` and push the registry live to every connected sensor, without
restarting `kbd` (see `docs/features/CWP.md`):
```bash
kbctl workload reload
```

`kbctl ssh session-start`/`session-end` also exist, but are not operator-facing
commands — they're the audit-tie-in callback the `sshd@kb-operator` `ForceCommand`
wrapper script invokes around every session (`docs/architecture/boot_sequence_spec.md`
§3), hidden from `--help` since there's no reason to run them by hand.

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

---

## 3. Service control and operator surfaces (packaged installs)

These commands drive systemd rather than gRPC, so they work even when `kbd` is down. They add `sudo` themselves when not root.

```bash
sudo kbctl up            # enable --now kbd, kb-sensor, kbopd, sshd@kb-operator (kb-checker is skipped)
sudo kbctl down          # stop them in reverse boot order (does not disable)
kbctl status             # unit states; kb-checker shows UNDER MAINTENANCE AND REPAIRS (kept down),
                         # or "active, STARTED MANUALLY" if someone started it by hand

kbctl dashboard up|down|status|url|open   # kbopd.service, http://127.0.0.1:8082
kbctl dashboard open     # starts it if needed and opens the browser with the API token as a URL fragment
kbctl dashboard url --token   # the same URL for another browser; treat the output as a secret
kbctl tui                # run the terminal UI on this terminal (exec kbopd)
kbctl ssh up|down|status      # sshd@kb-operator.service on port 2222
kbctl ssh connect [host] [-i key]   # exec ssh -t -p 2222 operator@host
sudo kbctl ssh add-key ~/.ssh/id_ed25519.pub   # append one validated public key to /etc/kb/authorized_keys
```

`dashboard status` and `ssh status` exit 0 only if the unit is active **and** the port answers, 3 otherwise, 1 on error (usable as health gates in scripts).

The dashboard's isolate / restore / policy-reload buttons need `KB_HTTP_API_TOKEN` on `kbd`. The package generates it into `/etc/kb/api.env` (root:kb 0640); `kbd.service` loads it and `kbctl dashboard open` hands it to the browser as a URL fragment (never sent to a server, kept in `sessionStorage`). Members of group `kb` can use `kba.sock` and therefore have full control-plane access.

Build: `cd kb-op/kbctl && go build -o kbctl .` (several files; `go build main.go` no longer works).

See `latex/field-manual/` (Chapters 7-12) for the full workflows.
