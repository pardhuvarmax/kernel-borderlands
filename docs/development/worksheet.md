# Control Plane & Operator Suite Collaboration Roadmap & Detailed Worksheet

This specification serves as the master architectural reference and step-by-step technical implementation guide for **Tejaswini (Go & Operators Lead)** and **Pardhu Varma (Systems & Security Lead)** to complete the L2/L3 integration phase of Kernel Borderlands.

---

## 📂 Master Index

1. [Architectural Context & Design Paradigms](#1-architectural-context--design-paradigms)
2. [Task 1: Go-to-C IPC Feedback & Containment Map](#2-task-1-go-to-c-ipc-feedback--containment-map) [COMPLETED]
3. [Task 2: Standard gRPC Health Checking Protocol](#3-task-2-standard-grpc-health-checking-protocol) [COMPLETED]
4. [Task 3: Process Exit Lifecycle (sched_process_exit)](#4-task-3-process-exit-lifecycle) [COMPLETED]
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

- **TASK-2 COMPLETED**

### B. Rust Subsystem Changes (`kb-checker/`) — *Pardhu Varma*

- **TASK-2 COMPLETED**

---

## 4. Task 3: Process Exit Lifecycle

### Context & Design Overview
In a containerized system, PIDs are recycled frequently. If the kernel does not emit a dedicated exit packet to the Go Control Plane, the L1 cache retains stale process parameters (e.g. associating PID 1234 with a benign program `nginx`). If PID 1234 is recycled by the OS and assigned to a malicious script, the control plane will evaluate the telemetry incorrectly using stale cache contexts.

By intercepting `sched_process_exit` directly in Ring 0, we can immediately flush the stale cache entry the moment the process terminates, preventing **PID recycling injection attacks**.

### A. C Subsystem Changes (`kb-core/`) — *Pardhu Varma*

- **TASK-3 COMPLETED**

### B. Go Subsystem Changes (`kb-control-plane/`) — *Tejaswini*

- **TASK-3 COMPLETED**

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
