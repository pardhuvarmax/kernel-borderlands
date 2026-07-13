# Engineering Task: kba.sock gRPC Unix Domain Socket Binding
**Target Developer**: Teju (Go Control Plane Lead)  
**Context**: Boot Sequence & Security Watchdog Integration  

---

## 1. Objective
To secure communications between the Go Control Plane (`kbd`), the Rust Safety Watchdog (`kb-checker`), and the Ray Swarm agent (`kbd-agent`), the control plane must bind its gRPC server to a Unix Domain Socket (UDS) located at `/run/kb/kba.sock` instead of (or in addition to) listening on TCP port `:50051`. 

This eliminates network exposure, implements local filesystem group access control, and allows standard systemd boot sequencing.

---

## 2. Required Go Code Modifications

The gRPC server listener is currently defined in `kb-control-plane/internal/controlplane/controlplane.go` under the `Start()` method. The following changes must be implemented:

### Step A: Update `controlplane.go` Imports
Ensure `os` and `syscall` packages are imported for handling socket file removals and permission modifications:
```go
import (
	"fmt"
	"log"
	"net"
	"os"
	"syscall"
	// other imports...
)
```

### Step B: Modify `Start()` to Bind Unix Socket
Replace the TCP listener binding with a Unix socket listener binding in `kb-control-plane/internal/controlplane/controlplane.go#L71`:

```go
// Start initiates the IPC listener and the gRPC server
func (cp *ControlPlane) Start() error {
	// 1. Start the userspace C sensor IPC listener
	go func() {
		if err := ipc.NewListener(cp).Listen(); err != nil {
			log.Fatalf("[KB] IPC: %v", err)
		}
	}()

	// 2. Bind gRPC Server to Unix Domain Socket
	socketPath := "/run/kb/kba.sock"
	
	// Clean up existing socket file if left over from previous crash
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Printf("[KB] Warning: failed to remove old socket file %s: %v", socketPath, err)
	}

	lis, err := net.Listen("unix", socketPath)
	if err != nil {
		// Fallback to TCP port :50051 if UDS path is unavailable (for local testing/macOS development)
		log.Printf("[KB] UDS bind failed: %v. Falling back to TCP :50051", err)
		lis, err = net.Listen("tcp", ":50051")
		if err != nil {
			return err
		}
	} else {
		// Apply safe permissions (0660) for service group access
		if err := os.Chmod(socketPath, 0660); err != nil {
			log.Printf("[KB] Warning: failed to chmod socket %s: %v", socketPath, err)
		}
	}

	cp.grpc = grpc.NewServer()
	pb.RegisterKernelBorderlandsServer(cp.grpc, cp)
	
	go func() {
		if lis.Addr().Network() == "unix" {
			log.Printf("[KB] gRPC listening on Unix Domain Socket: %s", socketPath)
		} else {
			log.Println("[KB] gRPC listening on TCP :50051")
		}
		cp.grpc.Serve(lis)
	}()

	log.Println("[KB] Control plane ready")
	return nil
}
```

### Step C: Update `Stop()` for Clean Shutdown
Ensure the socket file is unlinked when the control plane is stopped gracefully in `kb-control-plane/internal/controlplane/controlplane.go#L86`:

```go
// Stop stops the gRPC server and cleans up database handles
func (cp *ControlPlane) Stop() {
	cp.grpc.GracefulStop()
	cp.store.Close()
	
	// Clean up socket file
	socketPath := "/run/kb/kba.sock"
	if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
		log.Printf("[KB] Failed to clean up UDS file %s: %v", socketPath, err)
	} else {
		log.Printf("[KB] Cleaned up Unix socket %s", socketPath)
	}
}
```

---

## 3. Impact & Dependency Checks
1. **Watchdog Connection (`kb-checker`)**: The Rust watchdog is configured to connect to `/run/kb/kba.sock`. Once this change is compiled, `kb-checker` will establish a connection immediately at boot-time Phase 2.
2. **Ray Agent Connection (`kbd-agent`)**: Ray nodes must be configured to pass UDS paths (`unix:///run/kb/kba.sock`) to their gRPC dial options.
