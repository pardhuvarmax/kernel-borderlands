# Kernel Borderlands — Collaborative Development Worksheet

This worksheet serves as the step-by-step technical implementation guide for **Tejaswini (Go & Operators Lead)** and **Pardhu Varma (Systems & Security Lead)** to complete the L2/L3 integration phase.

---

## 🛠️ Work Sheet Index

- [Task 1: Go-to-C IPC Feedback & Containment Map](#task-1-go-to-c-ipc-feedback--containment-map)
- [Task 2: Standard gRPC Health Checking Protocol](#task-2-standard-grpc-health-checking-protocol)
- [Task 3: Process Exit Lifecycle (sched_process_exit)](#task-3-process-exit-lifecycle)
- [Task 4: SSH Wish Hardening & MCP Metrics](#task-4-ssh-wish-hardening--mcp-metrics)
- [Verification & Testing Suite](#verification--testing-suite)

---

## Task 1: Go-to-C IPC Feedback & Containment Map

### A. C Subsystem Changes (`kb-core/`) — *Pardhu Varma*
1.  **Define C Struct in `include/kb_common.h`**:
    Ensure the structure is packed to prevent padding shifts.
    ```c
    #define MSG_TYPE_CONTAINMENT_CMD 3

    struct __attribute__((packed)) kb_wire_containment_cmd {
        uint32_t pid;
        uint32_t level; // 0=None, 1=Cgroup, 2=Seccomp, 3=Namespace, 4=Terminate
        char reason[64];
    };
    ```
2.  **Define BPF Map in `ebpf/kbd_sensor.bpf.c`**:
    Define a hash map keyed by target PID:
    ```c
    struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 1024);
        __type(key, uint32_t);   // PID
        __type(value, uint32_t); // Containment Level
    } contained_pids_map SEC(".maps");
    ```
3.  **Implement Map Inspection in eBPF Syscall Hooks**:
    Inspect every targeted event (e.g. network connects or file access) against this map:
    ```c
    SEC("lsm/file_open")
    int BPF_PROG(kb_file_open, struct file *file, int mask) {
        uint32_t pid = bpf_get_current_pid_tgid() >> 32;
        uint32_t *level = bpf_map_lookup_elem(&contained_pids_map, &pid);
        if (level && *level >= 2) { // SECCOMP or higher
            return -EACCES; // Reject access
        }
        return 0;
    }
    ```
4.  **Implement Socket Listener in C Userspace (`userspace/sensor/kbd_sensor.c`)**:
    Update the main UDS read loop to poll for incoming containment commands, parse them, and write to the BPF map:
    ```c
    void handle_incoming_containment_cmd(int sock_fd) {
        struct kb_wire_containment_cmd cmd;
        if (recv(sock_fd, &cmd, sizeof(cmd), 0) == sizeof(cmd)) {
            uint32_t pid = cmd.pid;
            uint32_t level = cmd.level;
            bpf_map_update_elem(bpf_map__fd(skel->maps.contained_pids_map), &pid, &level, BPF_ANY);
            printf("[SENSOR] Applied containment level %d to PID %d\n", level, pid);
        }
    }
    ```

### B. Go Subsystem Changes (`kb-control-plane/`) — *Tejaswini*
1.  **Define Go Struct in `internal/ipc/types.go`**:
    ```go
    type ContainmentCmdMsg struct {
        PID    uint32
        Level  uint32
        Reason [64]byte
    }
    ```
2.  **Add Socket Write Method in `internal/ipc/listener.go`**:
    Track active client connections inside `Listener` and implement a safe, mutex-guarded write function:
    ```go
    type Listener struct {
        path  string
        ln    net.Listener
        mu    sync.Mutex
        conns map[net.Conn]bool
        Done  chan struct{}
    }

    func (l *Listener) SendContainmentCmd(pid uint32, level uint32, reason string) error {
        l.mu.Lock()
        defer l.mu.Unlock()

        var reasonBytes [64]byte
        copy(reasonBytes[:], []byte(reason))
        payload := ContainmentCmdMsg{PID: pid, Level: level, Reason: reasonBytes}

        // Header: Magic (0x4B42), Version (3), MsgType (MSG_TYPE_CONTAINMENT_CMD = 3)
        var header [4]byte
        binary.LittleEndian.PutUint16(header[0:2], 0x4B42)
        header[2] = 3
        header[3] = 3

        for conn := range l.conns {
            // Write length (uint32) followed by header and payload
            length := uint32(len(header) + 72) // 4 + 72
            binary.Write(conn, binary.LittleEndian, length)
            conn.Write(header[:])
            binary.Write(conn, binary.LittleEndian, payload)
        }
        return nil
    }
    ```
3.  **Update Go Enforcer (`internal/enforcement/enforce.go`)**:
    Route `SECCOMP` and `NAMESPACE` triggers to this UDS write helper instead of keeping them as stubs.

---

## Task 2: Standard gRPC Health Checking Protocol

### A. Go Subsystem Changes (`kb-control-plane/`) — *Tejaswini*
1.  **Initialize and Register Health Server in `internal/controlplane/controlplane.go`**:
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
        cp.healthServer.SetServingStatus("kb.KernelBorderlands", healthpb.HealthCheckResponse_SERVING)
        return nil
    }

    func (cp *ControlPlane) Stop() {
        cp.healthServer.SetServingStatus("kb.KernelBorderlands", healthpb.HealthCheckResponse_NOT_SERVING)
        cp.grpc.GracefulStop()
        cp.store.Close()
    }
    ```

### B. Rust Subsystem Changes (`kb-checker/`) — *Pardhu Varma*
1.  **Integrate Health client in safety checker**:
    Add `grpcio` or `tonic` health client check to `/run/kb/kbd.sock` UDS:
    ```rust
    use tonic::transport::{Endpoint, Uri};
    use tower::service_fn;
    use tokio::net::UnixStream;

    async fn check_control_plane_health() -> Result<(), Box<dyn std::error::Error>> {
        let channel = Endpoint::try_from("http://[::]:50051")?
            .connect_with_connector(service_fn(|_| async {
                UnixStream::connect("/run/kb/kbd.sock").await
            }))
            .await?;

        let mut client = grpc_health_v1::health_client::HealthClient::new(channel);
        let request = grpc_health_v1::HealthCheckRequest {
            service: "kb.KernelBorderlands".to_string(),
        };

        let response = tokio::time::timeout(
            tokio::time::Duration::from_millis(100),
            client.check(request)
        ).await??;

        if response.into_inner().status == grpc_health_v1::health_check_response::ServingStatus::Serving {
            Ok(())
        } else {
            Err("Control plane health status: NOT_SERVING".into())
        }
    }
    ```

---

## Task 3: Process Exit Lifecycle

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
        
        // Push exit_event to C userspace sensor ring buffer
        return 0;
    }
    ```
3.  **Forward Packet in C Userspace Loader**:
    Read the tracepoint payload from the ring buffer and write it directly over the UDS connection.

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
        cp.commCache.Delete(msg.PID)
        if err := cp.store.TerminateProcessState(msg.PID, msg.ExitTimeNs, msg.ExitCode); err != nil {
            log.Printf("[KB] store term: %v", err)
        }
        log.Printf("[KB] Process PID=%d terminated (Code: %d)", msg.PID, msg.ExitCode)
    }
    ```
4.  **Update L2 Database in `internal/store/store.go`**:
    ```go
    func (s *Store) TerminateProcessState(pid uint32, exitTime int64, code uint32) error {
        // Run SQL transaction: update process status column to 'TERMINATED'
    }
    ```

---

## Task 4: SSH Wish Hardening & MCP Metrics

### A. TUI SSH Hardening (`kb-op/kb-tui/`) — *Tejaswini*
1.  **Generate persistent SSH host keys**:
    Create `/etc/kb/tui_host_key` to avoid regenerating keys on every TUI console reload.
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
1.  **Expose Statistics via `kb.get_statistics`**:
    Query gRPC endpoints on the Control Plane to return client counts and pipeline status:
    ```go
    func getSystemStatistics() string {
        // Query cp.GetSystemStats() via gRPC client
        // Format payload into JSON structure for AI client consumption
    }
    ```

---

## 🧪 Verification & Testing Suite

Execute these tests in order to validate all collaborative milestones:

1.  **eBPF Build Checks**:
    ```bash
    cd kb-core && make clean && make
    ```
2.  **Go Daemon Unit Testing**:
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
    ```bash
    cd kb-checker && cargo test
    ```
