# Control Plane & Operator Suite Collaboration Roadmap Specification

This specification outlines the technical details, packet structures, gRPC changes, and workflow steps required to complete the integration of the Go Control Plane (`kb-control-plane`) with the eBPF layer (`kb-core`), the Safety Daemon (`kb-checker`), and the Operator Interfaces.

---

## 1. Task 1: Go-to-C Containment Feedback Loop

### Context
Currently, the Go Control Plane is a passive receiver of telemetry. When containment actions (e.g. `SECCOMP` or `NAMESPACE` isolation) are requested via `kbctl` or `kb-dashboard`, Go stubs these operations. We need to implement a feedback channel where Go writes containment commands back to the C userspace loader, which updates Ring 0 eBPF blocking maps.

```text
  [Operator / CLI / AI]
           │ (gRPC)
           ▼
  [Go Control Plane (kbd)]
           │ (UDS Write: /run/kb/kbd.sock)
           ▼
  [C Userspace Sensor (kbd_sensor)]
           │ (BPF Map Update)
           ▼
  [eBPF Containment Maps] ──► Restricts Syscalls/LSM in Ring 0
```

### Packet Definition (C & Go Struct Alignment)
The containment payload must be prefixed by the standard header: Magic `0x4B42` (2 bytes), Version `3` (1 byte), Message Type `MSG_TYPE_CONTAINMENT_CMD = 3` (1 byte).

```c
// C representation in kb_common.h
struct __attribute__((packed)) kb_wire_containment_cmd {
    uint32_t pid;
    uint32_t level; // 0=None, 1=Cgroup, 2=Seccomp, 3=Namespace, 4=Terminate
    char reason[64];
};
```

```go
// Go representation in internal/ipc/types.go
type ContainmentCmdMsg struct {
    PID    uint32
    Level  uint32
    Reason [64]byte
}
```

### Go Implementation Steps (Tejaswini)
1. In `internal/ipc/listener.go`, expose a write channel on the active Unix Domain Socket connection:
   ```go
   func (l *Listener) SendContainmentCmd(pid uint32, level uint32, reason string) error {
       // Locate the active connection, serialize kb_wire_containment_cmd, and write to UDS
   }
   ```
2. In `internal/enforcement/enforce.go`, update `Apply` to route commands to the UDS write channel:
   ```go
   func (e *Enforcer) Apply(pid uint32, level pb.ContainmentLevel) {
       // Send ContainmentCmdMsg over UDS for SECCOMP and NAMESPACE levels
   }
   ```

### C/eBPF Implementation Steps (Pardhu Varma)
1. Declare a BPF map in `kbd_sensor.bpf.c` for tracking quarantined PIDs:
   ```c
   struct {
       __uint(type, BPF_MAP_TYPE_HASH);
       __uint(max_entries, 1024);
       __type(key, uint32_t);   // PID
       __type(value, uint32_t); // Containment Level
   } contained_pids_map SEC(".maps");
   ```
2. In `kbd_sensor.c` (userspace), read incoming commands from the socket and call `bpf_map_update_elem` on `contained_pids_map`.

---

## 2. Task 2: gRPC Health Checking Protocol

### Context
The Rust-based `kb-checker` Safety Daemon must verify the availability of the Go Control Plane over the UDS socket. To do this without custom authentication or heavy parsing, we will implement the standard **gRPC Health Checking Protocol**.

### Go Implementation Steps (Tejaswini)
1. Import the standard health packages in `internal/controlplane/controlplane.go`:
   ```go
   import (
       "google.golang.org/grpc/health"
       healthpb "google.golang.org/grpc/health/grpc_health_v1"
   )
   ```
2. In `Start()`, initialize the health server and register it on the gRPC engine:
   ```go
   healthServer := health.NewServer()
   healthpb.RegisterHealthServer(cp.grpc, healthServer)
   // Set status to serving
   healthServer.SetServingStatus("kb.KernelBorderlands", healthpb.HealthCheckResponse_SERVING)
   ```
3. Update `Stop()` to mark the status as `NOT_SERVING` during teardown.

### Rust Integration Steps (Pardhu Varma)
Update `kb-checker`'s control plane audit loop (`Loop2`) to issue standard gRPC health checks against `/run/kb/kbd.sock` with a strict `100ms` connection and reply deadline.

---

## 3. Task 3: Process Exit Lifecycle (MSG_TYPE_PROCESS_EXIT)

### Context
When a monitored process exits, eBPF captures the event. However, the Go Control Plane is not notified of the exit directly, resulting in L1 cache (`sync.Map`) retaining stale data until a PID wrap occurs. We need a dedicated process exit wire packet.

### Packet Definition
Header: Magic `0x4B42`, Version `3`, Message Type `MSG_TYPE_PROCESS_EXIT = 4`.

```c
// C representation in kb_common.h
struct __attribute__((packed)) kb_wire_process_exit {
    uint32_t pid;
    int64_t  exit_time_ns;
    uint32_t exit_code;
};
```

```go
// Go representation in internal/ipc/types.go
type ProcessExitMsg struct {
    PID        uint32
    ExitTimeNs int64
    ExitCode   uint32
}
```

### Implementation Steps
1. **Pardhu Varma (C side)**:
   * Bind an eBPF tracepoint to `sched/sched_process_exit`.
   * When triggered, extract the PID and exit code, and send it to the userspace loader via the ring buffer.
   * Userspace C loader serializes `kb_wire_process_exit` and pushes it over the UDS socket to Go.
2. **Tejaswini (Go side)**:
   * Implement `OnProcessExit(msg *ipc.ProcessExitMsg)` in `controlplane.go`.
   * Delete the PID from the L1 `commCache` and in-memory stores.
   * Execute an L2 store query to update the process state status column to `TERMINATED` in the SQLite WAL database.

---

## 4. Task 4: Operator SSH TUI Hardening & MCP Metrics

### Context
The Operator TUI (`kb-tui`) and MCP server (`kb-mcp`) must be hardened for secure staging and expose broader instrumentation metrics.

### Implementation Steps (Tejaswini)
1. **Wish SSH Gateway Key Configuration**:
   * Migrate `/kb-op/kb-tui/cmd/main.go` from using dynamic ephemeral keys to utilizing a persistent host key path (e.g. `/etc/kb/tui_host_key`).
   * Add a configuration parser to restrict authorized keys using standard `authorized_keys` listings:
     ```go
     // In Wish server options:
     wish.WithPublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
         // Validate public key fingerprint against permitted operator lists
     })
     ```
2. **MCP Statistics Resource Mapping**:
   * Map database metrics, active WebSocket client counts, and Safety Engine heartbeats into the `kb.get_statistics` tool handler within `kb-op/kb-mcp/main.go`.
