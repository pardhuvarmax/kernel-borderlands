# Boot Sequence & Daemon Lifecycle Specification

This document defines the boot-time initialization sequence, socket ownership boundaries, and systemd service dependency mapping for the Kernel Borderlands (KB) platform. It ensures race-free service starts and guarantees security hooks are attached to the kernel before untrusted user space applications boot.

---

## 1. Architectural Sockets & Files

The Kernel Borderlands system relies on three primary Unix Domain Sockets (UDS) located in the `/run/kb/` runtime directory. The ownership, permission bounds, and creators are strictly defined as follows:

| Socket/File Path | Owner | Group | Permissions | Binding Process | Purpose |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/run/kb/kbd.sock` | `root` | `kb-devs` | `0660` | `kbd` (Go Control Plane) | Binary telemetry pipe for eBPF events from `kbd_sensor` to Go. |
| `/run/kb/kba.sock` | `root` | `kb-devs` | `0660` | `kbd` (Go Control Plane) | gRPC IPC socket for client registrations and enforcer directives. |
| `/run/kb/kbc.sock` | `root` | `kb-devs` | `0660` | `kb-checker` (Rust) | gRPC IPC socket for health diagnostic reporting to TUIs/CLIs. |
| `/run/kb/kb-checker.pid` | `root` | `root` | `0600` | `kb-checker` (Rust) | File lock preventing duplicate active safety daemons. |

---

## 2. Boot Timeline Sequence

```mermaid
sequenceDiagram
    autonumber
    participant Systemd as Linux Boot / Systemd
    participant KBD as Go Control Plane (kbd)
    participant Kernel as eBPF Kernel Hooks
    participant KBC as Rust Safety Daemon (kb-checker)
    participant AADS as Ray Swarm / AADS Node

    Note over Systemd, AADS: Phase 1: Core Control Plane Boot
    Systemd->>KBD: Start kbd.service
    activate KBD
    KBD->>KBD: Create /run/kb/kbd.sock & kba.sock
    KBD->>Kernel: Load & attach unified eBPF sensors (kbd_sensor)
    activate Kernel
    KBD-->>Systemd: Notify readiness (sd_notify)
    deactivate KBD

    Note over Systemd, AADS: Phase 2: Safety Layer Activation
    Systemd->>KBC: Start kb-checker.service
    activate KBC
    KBC->>KBC: Create /run/kb/kbc.sock & lock kb-checker.pid
    KBC->>KBD: Establish gRPC client connection over kba.sock
    KBC->>Kernel: Run initial JIT signature & map audit
    KBC-->>Systemd: Daemon running safely
    deactivate KBC

    Note over Systemd, AADS: Phase 3: Infrastructure Boot
    Systemd->>AADS: Start Ray Cluster / Node Agent
    activate AADS
    AADS->>KBD: Register node via kba.sock gRPC
    AADS->>KBC: Query safety telemetry over kbc.sock
    deactivate AADS
```

### Phase 1: Core Control Plane Boot
1. **Service Launch**: Systemd starts the Go control plane daemon (`kbd.service`).
2. **Socket Setup**: `kbd` creates the `/run/kb/` directory (if not present) and binds the `kbd.sock` and `kba.sock` UNIX domain sockets.
3. **eBPF Loading**: `kbd` invokes `kb-core-loader` to compile, load, and attach `kbd_sensor.bpf.c` tracepoints and LSM hooks to the kernel.
4. **Readiness Signal**: `kbd` sends a readiness notification (`sd_notify`) back to Systemd, indicating that the IPC sockets are fully open and ready.

### Phase 2: Safety Layer Activation
1. **Safety Launch**: Systemd starts the Rust Safety Daemon (`kb-checker.service`). This service is configured to run strictly `After=kbd.service`.
2. **Single-Instance Protection**: `kb-checker` acquires an exclusive POSIX `flock` on `/run/kb/kb-checker.pid`. If blocked, the service aborts.
3. **Diagnostic Socket binding**: `kb-checker` binds `/run/kb/kbc.sock` to expose the diagnostic endpoint.
4. **Initial Verification**: `kb-checker` executes immediate blocking checks for:
   * **eBPF Bytecode Integrity**: Scans memory JIT signatures against `/etc/kb/ebpf_policies.json`.
   * **eBPF Hook Liveness**: Verifies the telemetry path by injecting a heartbeat process.
   * **BPF Map Integrity**: Verifies containment map flags in `/run/kb/contained_pids_map`.
5. **Operational State**: Once checks pass, the checker begins its scheduled auditing loops.

### Phase 3: Infrastructure Boot
1. **User Space App Activation**: The system transitions to the multi-user target, allowing AADS swarm nodes and local monitoring TUIs to start.
2. **Agent Registrations**: The Ray Node Agent connects to `/run/kb/kba.sock` to submit process registrations.
3. **Continuous Auditing**: Sockets and kernel performance are audited asynchronously by the checker.

---

## 3. Production Systemd Service Unit Files

These unit files define the exact dependencies required to establish the boot sequence:

### `/etc/systemd/system/kbd.service`
```ini
[Unit]
Description=Kernel Borderlands Go Control Plane Daemon
Before=kb-checker.service
DefaultDependencies=no
After=local-fs.target

[Service]
Type=notify
ExecStart=/usr/local/bin/kbd --config /etc/kb/config.yaml
Restart=always
RestartSec=3
RuntimeDirectory=kb
RuntimeDirectoryMode=0775

[Install]
WantedBy=multi-user.target
```

### `/etc/systemd/system/kb-checker.service`
```ini
[Unit]
Description=Kernel Borderlands Safety and Integrity Watchdog Daemon
After=kbd.service
Requires=kbd.service
DefaultDependencies=no

[Service]
Type=simple
ExecStart=/usr/local/bin/kb-checker monitor --all --grpc-socket /run/kb/kbc.sock
Restart=always
RestartSec=5
PIDFile=/run/kb/kb-checker.pid

[Install]
WantedBy=multi-user.target
```

---

## 4. Race Conditions & Fail-Safe Paths

### eBPF Hook Loading Failure
* **Scenario**: The kernel lacks LSM support or `kbd` fails to attach `kbd_sensor`.
* **Behavior**: `kbd.service` fails to send the readiness signal to Systemd and terminates. `kb-checker.service` (which requires `kbd.service`) will not start, preventing the node from registering as functional.

### UDS Socket Connection Loss
* **Scenario**: `kbd` is restarted, temporarily deleting `/run/kb/kba.sock`.
* **Behavior**: `kb-checker` loops detect connection failures on `kba.sock`. The checker logs warnings and enters a retry state. If the socket remains missing for over **15 seconds**, it triggers emergency bytecode reloads and raises a kernel containment alert.

### Double Daemon Execution
* **Scenario**: An operator or malicious process attempts to run `kb-checker monitor` manually while the systemd service is active.
* **Behavior**: The manual instance fails to acquire the POSIX `flock` on `/run/kb/kb-checker.pid` and aborts immediately, keeping the primary safety daemon intact.

### Graceful Termination
* **Scenario**: A system administrator stops the watchdog daemon (`systemctl stop kb-checker`).
* **Behavior**: `kb-checker` catches the `SIGTERM` signal, terminates the active auditing loops, closes the gRPC server, and cleans up `/run/kb/kbc.sock` and `/run/kb/kb-checker.pid`.

---

## 5. Tampering Containment & Workload Gating

To secure the platform against early-boot compromises, the boot sequence enforces a strict division between the **Control Plane** (communication gateway), the **Core Subsystem** (eBPF telemetry), and the **AADS Subsystem** (Ray agent workloads). 

```mermaid
graph TD
    A[Tampering Detected during Boot] --> B{Tampered Element?}
    B -->|eBPF Bytecode or Hook Liveness| C[Halting Core Subsystem]
    C --> C1[Unload kbd_sensor from Kernel]
    C --> C2[Send integrity violation state & stack trace to kbd Control Plane]
    C2 --> C3[kbd forwards alert to Operator Console]
    C3 --> C4[System enters Quarantine: Only Control Plane active]
    
    B -->|kb-checker kbc fails to start| D[Halting AADS Subsystem]
    D --> D1[Systemd blocks kbd-agent / Ray Agent startup]
    D1 --> D2[Workload execution denied]
    D2 --> D3[System enters Quarantine: Only Control Plane active]
```

### Scenario A: eBPF Program Integrity Violation (Liveness / Signature Tampering)
If `kb-checker` detects an eBPF integrity violation (signature hash mismatch in memory or liveness heartbeat bypass) during the initial Phase 2 checks:
1. **Emergency Halting of Core Subsystem**: `kb-checker` immediately triggers a command to unload and remove the `kbd_sensor` bytecode from kernel memory (using `kb-core-loader --unload`). This ensures that compromised or hijacked sensors are prevented from running or providing spoofed telemetry.
2. **Detailed Diagnostic Reporting**: The checker compiles a diagnostic dump, including:
   * The program name that failed validation.
   * Expected vs. actual SHA-256 bytecode signature hashes.
   * A call stack trace of the validation failure event.
3. **Control Plane Communication**: This report is dispatched over the UDS `/run/kb/kba.sock` to the Go Control Plane (`kbd`). 
4. **Operator Propagation**: The Go Control Plane remains active, logs the critical error, and broadcasts the `INTEGRITY_VIOLATION_CONTAIN` status to the central Operator Console.
5. **System State**: The node remains online exclusively for diagnostic query, but the core sensor monitoring is terminated to prevent false security signals.

### Scenario B: `kb-checker` (kbc) Daemon Failure
If the safety watchdog daemon `kb-checker` crashes, is killed, or fails to initialize successfully:
1. **AADS Subsystem Halt**: Because the Ray Swarm agent (`kbd-agent.service`) has a strict systemd dependency chaining of `Requires=kb-checker.service` and `After=kb-checker.service`, the Ray agent is completely blocked from starting.
2. **Workload Denial**: No ML agent distributed workloads are allowed to execute on the node.
3. **System State**: The node is quarantined from the Ray Swarm cluster. The Go Control Plane (`kbd.service`) stays active, allowing administrators to query the system state remotely over `kba.sock` to diagnose the watchdog crash.

