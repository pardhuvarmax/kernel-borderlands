# Control Plane & Operator Suite Collaboration Roadmap & Detailed Worksheet

This specification serves as the master architectural reference and step-by-step technical implementation guide for **Tejaswini (Go & Operators Lead)** and **Pardhu Varma (Systems & Security Lead)** to complete the L2/L3 integration phase of Kernel Borderlands.

---

## 📂 Master Index

1. [Architectural Context & Design Paradigms](#1-architectural-context--design-paradigms)
2. [Task 1: Go-to-C IPC Feedback & Containment Map](#2-task-1-go-to-c-ipc-feedback--containment-map) [COMPLETED]
3. [Task 2: Standard gRPC Health Checking Protocol](#3-task-2-standard-grpc-health-checking-protocol)
4. [Task 3: Process Exit Lifecycle (sched_process_exit)](#4-task-3-process-exit-lifecycle)
5. [Task 4: SSH Wish Hardening & MCP Metrics](#5-task-4-ssh-wish-hardening--mcp-metrics)
6. [Verification & Testing Suite](#6-verification--testing-suite)

---

## 1. Architectural Context & Design Paradigms

Before implementing the tasks outlined below, the development team must align on the underlying design paradigms that govern Kernel Borderlands (KB):

*   **Ring Zero Enforcement Authority**: Userspace is too slow and too privileged-isolated to reliably block attacks once they have already progressed. Real-time blocking (such as file or network access denial) must occur directly within the kernel using eBPF LSM and syscall handlers. 
*   **State Synchronization without Polling**: Polling loops introduce unacceptable CPU overhead on production servers. All communications between `kb-core` (C) and `kb-control-plane` (Go) occur over a bi-directional, event-driven Unix Domain Socket (UDS) connection, minimizing system interrupts.
*   **Memory Space Alignment**: Go runs in a managed, garbage-collected runtime; C and eBPF operate in unmanaged kernel memory. To bridge these systems, all network structures must be compiled with strict alignment (`__attribute__((packed))`) to ensure that differences in word size and struct padding between C and Go do not corrupt telemetry frames.

---

## 2. Task 1: Go-to-C IPC Feedback & Containment Map

### Context & Design Overview
In the initial development phase, the Go Control Plane acted as a passive receiver. To close the control loop, we implement a feedback channel. When an operator triggers a containment override (e.g. `SECCOMP` or `NAMESPACE` isolation), the Go daemon writes a command structure down the UDS socket. The C loader reads this packet and updates a BPF map.

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

Using a BPF map (`contained_pids_map`) for containment is significantly more resilient than standard userspace containment (like launching scripts to freeze cgroups or sending signals):
*   **Zero-Window Bypass Guard**: By checking the map directly inside LSM hooks (`bpf_lsm_file_open`), we ensure that even if an attacker attempts to fork rapidly to bypass standard PID limits, the kernel intercepts the operation instantly.
*   **Low Execution Overhead**: A BPF map lookup takes only a few nanoseconds, introducing negligible performance impact to hot path syscalls.

### A. C Subsystem Changes (`kb-core/`) — *Pardhu Varma*

- **TASK-1 COMPLETED**

### B. Go Subsystem Changes (`kb-control-plane/`) — *Tejaswini*

- **TASK-1 COMPLETED**

---

## 3. Task 2: Standard gRPC Health Checking Protocol

### Context & Design Overview
The Rust-based `kb-checker` Safety Daemon monitors the Control Plane socket. Instead of writing custom ping RPCs, we will implement the standard **gRPC Health Checking Protocol (v1)**. 

Using this standard provides key advantages:
*   **Infrastructure Native**: Standard health check clients (like `grpc-health-probe`) can inspect the daemon out of the box.
*   **Decoupled Audits**: The checker does not need administrative privileges or authentication keys to perform basic availability audits, keeping credentials out of the safety loop.

### A. Go Subsystem Changes (`kb-control-plane/`) — *Tejaswini*
1.  **Register Health Server in `internal/controlplane/controlplane.go`**:
    Import the standard health check packages and register the service during Start:
    ```go
    import (
        "google.golang.org/grpc/health"
        healthpb "google.golang.org/grpc/health/grpc_health_v1"
    )

    type ControlPlane struct {
        // ...
        healthServer *health.Server
    }

    func (cp *ControlPlane) Start() error {
        // ...
        cp.healthServer = health.NewServer()
        healthpb.RegisterHealthServer(cp.grpc, cp.healthServer)
        
        // Mark the primary service status as SERVING
        cp.healthServer.SetServingStatus("kb.KernelBorderlands", healthpb.HealthCheckResponse_SERVING)
        return nil
    }

    func (cp *ControlPlane) Stop() {
        // Mark as NOT_SERVING prior to shutting down sockets
        cp.healthServer.SetServingStatus("kb.KernelBorderlands", healthpb.HealthCheckResponse_NOT_SERVING)
        cp.grpc.GracefulStop()
        cp.store.Close()
    }
    ```

### B. Rust Subsystem Changes (`kb-checker/`) — *Pardhu Varma*
1.  **Integrate Health client in Safety Daemon**:
    Implement a non-blocking Unix Domain Socket dialer in Rust to perform check queries:
    ```rust
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;
    use tokio::net::UnixStream;

    async fn check_control_plane_health() -> Result<(), Box<dyn std::error::Error>> {
        // Dial the Unix domain socket instead of standard TCP URI
        let channel = Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(service_fn(|_| async {
                UnixStream::connect("/run/kb/kbd.sock").await
            }))
            .await?;

        let mut client = grpc_health_v1::health_client::HealthClient::new(channel);
        let request = grpc_health_v1::HealthCheckRequest {
            service: "kb.KernelBorderlands".to_string(),
        };

        // Enforce a strict 100ms deadline
        let response = tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            client.check(request)
        ).await??;

        if response.into_inner().status == grpc_health_v1::health_check_response::ServingStatus::Serving {
            Ok(())
        } else {
            Err("Control plane reported state: NOT_SERVING".into())
        }
    }
    ```

---

## 4. Task 3: Process Exit Lifecycle

### Context & Design Overview
In a containerized system, PIDs are recycled frequently. If the kernel does not emit a dedicated exit packet to the Go Control Plane, the L1 cache retains stale process parameters (e.g. associating PID 1234 with a benign program `nginx`). If PID 1234 is recycled by the OS and assigned to a malicious script, the control plane will evaluate the telemetry incorrectly using stale cache contexts.

By intercepting `sched_process_exit` directly in Ring 0, we can immediately flush the stale cache entry the moment the process terminates, preventing **PID recycling injection attacks**.

### A. C Subsystem Changes (`kb-core/`) — *Pardhu Varma*
1.  **Define C Struct in `include/kb_common.h`**:
    ```c
    #define MSG_TYPE_PROCESS_EXIT 4

    struct __attribute__((packed)) kb_wire_process_exit {
        uint32_t pid;
        int64_t  exit_time_ns;
        uint32_t exit_code;
    };
    ```
2.  **Add Exit Hook in `ebpf/kbd_sensor.bpf.c`**:
    Bind a tracepoint to capture kernel exits:
    ```c
    SEC("tracepoint/sched/sched_process_exit")
    int kb_sched_process_exit(void *ctx) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        uint32_t pid = bpf_get_current_pid_tgid() >> 32;
        
        struct kb_wire_process_exit exit_event = {
            .pid = pid,
            .exit_time_ns = bpf_ktime_get_ns(),
            .exit_code = task->exit_code
        };
        
        // Push the exit_event struct to C userspace ring buffer
        bpf_ringbuf_output(&exit_events_ringbuf, &exit_event, sizeof(exit_event), 0);
        return 0;
    }
    ```
3.  **Forward Packet in C Userspace Loader**:
    The userspace C sensor reads the exit frame from the ring buffer and writes it directly to the UDS connection.

### B. Go Subsystem Changes (`kb-control-plane/`) — *Tejaswini*
1.  **Define Go Struct in `internal/ipc/types.go`**:
    ```go
    type ProcessExitMsg struct {
        PID        uint32
        ExitTimeNs int64
        ExitCode   uint32
    }
    ```
2.  **Handle Packet inside Go Listener (`internal/ipc/listener.go`)**:
    Add `MSG_TYPE_PROCESS_EXIT = 4` case route to the packet decoder:
    ```go
    case 4: // MSG_TYPE_PROCESS_EXIT
        var exitFrame ProcessExitMsg
        binary.Read(buf, binary.LittleEndian, &exitFrame)
        l.handler.OnProcessExit(&exitFrame)
    ```
3.  **Process Termination in `controlplane.go`**:
    ```go
    func (cp *ControlPlane) OnProcessExit(msg *ipc.ProcessExitMsg) {
        // Delete volatile cache entries to prevent PID reuse vulnerabilities
        cp.commCache.Delete(msg.PID)
        
        // Push exit details to L2 DB
        if err := cp.store.TerminateProcessState(msg.PID, msg.ExitTimeNs, msg.ExitCode); err != nil {
            log.Printf("[KB] store term: %v", err)
        }
        log.Printf("[KB] Process PID=%d terminated (Code: %d)", msg.PID, msg.ExitCode)
    }
    ```
4.  **Update L2 Database in `internal/store/store.go`**:
    Execute an SQLite query to mark the process status:
    ```go
    func (s *Store) TerminateProcessState(pid uint32, exitTime int64, code uint32) error {
        _, err := s.db.Exec(`
            UPDATE process_states 
            SET status = 'TERMINATED', last_seen = ?, exit_code = ? 
            WHERE pid = ? AND status = 'RUNNING'
        `, exitTime, code, pid)
        return err
    }
    ```

---

## 5. Task 4: SSH Wish Hardening & MCP Metrics

### Context & Design Overview
`kb-tui` uses Wish (an SSH library). By default, developer configurations regenerate host keys on startup. This causes client SSH clients to warn operators of a potential "Man-in-the-Middle" (MITM) attack on every console reload. To productize the workflow, we must load a persistent host key and validate authorized public keys.

### A. TUI SSH Hardening (`kb-op/kb-tui/`) — *Tejaswini*
1.  **Generate persistent SSH host keys**:
    Create `/etc/kb/tui_host_key` to avoid regenerating keys.
2.  **Update TUI Server Configuration**:
    ```go
    import "github.com/charmbracelet/wish"

    func StartSSH() {
        s, err := wish.NewServer(
            wish.WithAddress("0.0.0.0:2222"),
            wish.WithHostKeyPath("/etc/kb/tui_host_key"),
            wish.WithPublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
                return validateAuthorizedKeys(key)
            }),
        )
    }
    ```

### B. MCP Metrics Integration (`kb-op/kb-mcp/`) — *Tejaswini*
Expose statistics via `kb.get_statistics` by querying gRPC endpoints on the Control Plane:
```go
func getSystemStatistics() string {
    // Query cp.GetSystemStats() via gRPC client
    // Format payload into JSON structure for AI client consumption
}
```

---

## 6. Verification & Testing Suite

Execute these tests in order to validate all collaborative milestones:

1.  **eBPF Build Checks**:
    Ensure the C codebase and BPF skeleton compile cleanly:
    ```bash
    cd kb-core && make clean && make
    ```
2.  **Go Daemon Unit Testing**:
    Ensure Go structures decode correctly:
    ```bash
    cd kb-control-plane && go test ./...
    ```
3.  **Simulated Containment Integration Test**:
    *   Trigger manual quarantine on a simulated PID:
        ```bash
        ./kbctl process isolate --pid 9999 --reason "Simulated threat"
        ```
    *   Verify that `kb-core`'s C loader reports incoming write packets and updates the BPF map correctly.
4.  **Simulated Process Exit Test**:
    *   Spawn a short-lived test program.
    *   Query the Go L2 store history (`./kbctl stats` or SQLite WAL direct inspect) and verify that the status has moved from `RUNNING` to `TERMINATED`.
5.  **Rust Checker gRPC Health Audits**:
    Ensure the safety checker verifies UDS connections within the 100ms deadline:
    ```bash
    cd kb-checker && cargo test
    ```
