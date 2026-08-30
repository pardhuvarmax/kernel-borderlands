# KB Control Plane — kbd Daemon

The userspace management daemon that mediates between the Ring 0 eBPF observation layer (`kb-core`), the AADS agentic swarm, and the local enforcement subsystems.

---

## Subsystem Architecture

### 1. Two-Tier Hybrid Storage (ADR-1)
To handle high-throughput system events without adding I/O latency:
*   **L1 Cache (In-Memory)**: Backed by `sync.Map`. Provides ultra-low latency ($\sim 30\text{--}50\text{ ns}$) access on the event-ingestion hot path. Used for real-time enforcement and timing verification.
*   **L2 Database (SQLite WAL)**: A durable SQLite database utilizing Write-Ahead Logging (WAL) and single-writer serialization (`SetMaxOpenConns(1)`) to avoid locking overhead. Stores audit logs and historical states.
*   **Cold-Start Recovery**: Rebuilds L1 memory state from L2 SQLite database upon daemon restart to preserve context.

### 2. IPC Wire Protocol (Unix Domain Socket Bridge)
Communicates with `kbd_sensor` over **two** Unix sockets, split by direction — `/run/kb/kbd.sock` (telemetry, sensor → Go, one-way) and `/run/kb/kbct.sock` (control pushes — containment commands, sensitive-path pushes — Go → sensor, one-way). Split so a telemetry-volume burst can never stall or kill containment delivery; see `docs/development/core-control/control-plane-catalog.md` §5.3. (Formerly one socket, `/var/run/kbd.sock`, carrying both directions.)
*   **Header Magic**: `0x4B42` (Little Endian).
*   **Wire Version**: `3`.
*   **Packed Structural Layouts**:
    -   `ProcessState` $\to$ Exactly **128 bytes** (LE, Packed).
    -   `ZoneTransition` $\to$ Exactly **40 bytes** (LE, Packed).
    -   `kb_wire_attack_rule` $\to$ Exactly **220 bytes** (LE, Packed).
*   **Dynamic Rules Handshake**: `internal/ipc/rules.go`'s `SendRulesPayload` (compiles `rules.yaml`, transmits over the bridge) is now wired into `ipc.Listener`'s connect-time push, same as the sensitive-paths push (`SendSensitivePaths`) — both fire from `pushConnectTimeFrames` on every new sensor connection over `kbct.sock`. **Send order is load-bearing, not incidental**: `kbd_sensor.c`'s handshake reads rules first, then sensitive paths — only the second read has a stash-based fallback for "the wrong frame arrived here," so rules must be sent first on the wire or the connection's later framing gets corrupted. Configured via `kbd --rules` (default `config/rules.yaml`; empty disables the push, sensor falls back to its compiled-in default rules).

### 3. SSH access to `kb-tui` — not hosted by `kbd`
Remote operator access to `kb-tui` (port 2222) is **not** served by `kbd` — there is no
SSH server in this daemon. A dedicated, independent `sshd` instance
(`sshd@kb-operator.service`) owns that port entirely, with `ForceCommand /usr/local/bin/kb-tui`
landing an authenticated operator directly in the console — real OpenSSH host keys,
`authorized_keys` parsing, and PTY allocation, none of it Go code in this repo. This
supersedes an earlier design where `kbd` hosted an in-process Go SSH server
(`internal/ssh/`, since deleted) — see `docs/development/core-control/control-plane-catalog.md`
§2.11 for why, and `docs/architecture/boot_sequence_spec.md` §3 for the actual unit/config
files. `kbd` and this `sshd` instance have no runtime dependency on each other.

---

## Directory Structure
*   **`cmd/kbd/`**: Daemon executable entrypoint.
*   **`internal/controlplane/`**: Core daemon runtime and gRPC handlers.
*   **`internal/store/`**: L1/L2 hybrid database state store.
*   **`internal/ipc/`**: UDS wire parsing, socket listeners, and rules serialization.
*   **`internal/policy/`**: Threshold policies and auto-containment configuration.
*   **`internal/audit/`**: Cryptographically chained, tamper-evident audit logger.

---

## Development & Test

### Run Unit Tests
To run all tests with cache disabled:
```bash
go test -v -count=1 ./...
```
*(All tests run in-memory using `:memory:` SQLite connections to isolate state).*

### Build and Run Daemon
Build the control plane executable:
```bash
go build -o kbd cmd/kbd/main.go
```
Run the daemon specifying a custom SQLite state database path:
```bash
./kbd --db data/state.db --policy config/policy.yaml
```

---

## Contributors & Subsystem Owners
*   **Tejaswini** — Defensive Pipelines, Control Plane Daemon & Communication (`kbd` Lead)
*   **Pardhu Varma** — Security Subsystems, gRPC, cGo (Collaboration)
