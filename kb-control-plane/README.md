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
Communicates with `kbd_sensor` over `/tmp/kbd.sock` (formerly `/var/run/kbd.sock`):
*   **Header Magic**: `0x4B42` (Little Endian).
*   **Wire Version**: `3`.
*   **Packed Structural Layouts**:
    -   `ProcessState` $\to$ Exactly **128 bytes** (LE, Packed).
    -   `ZoneTransition` $\to$ Exactly **40 bytes** (LE, Packed).
    -   `kb_wire_attack_rule` $\to$ Exactly **220 bytes** (LE, Packed).
*   **Dynamic Rules Handshake**: On connection start, Go compiles `rules.yaml` and transmits them over the bridge to dynamically update the C sensor's behavior rules list.

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
