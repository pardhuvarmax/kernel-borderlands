# Engineering Task: kba.sock gRPC Unix Domain Socket Binding
**Target Developer**: Teju (Go Control Plane Lead)  
**Context**: Boot Sequence & Security Watchdog Integration  
**Status:** Completed — implemented in `kb-control-plane/internal/controlplane/controlplane.go` (`listenUnix`), no TCP fallback.

---

## 1. Objective
To secure communications between the Go Control Plane (`kbd`), the Rust Safety Watchdog (`kb-checker`), and the Ray Swarm agent (`kbd-agent`), the control plane must bind its gRPC server to a Unix Domain Socket (UDS) located at `/run/kb/kba.sock`. There is no TCP fallback — UDS is the only transport, everywhere, including local/dev environments.

This eliminates network exposure, implements local filesystem group access control, and allows standard systemd boot sequencing.

---

## 2. Required Go Code Modifications

The gRPC server listener is currently defined in `kb-control-plane/internal/controlplane/controlplane.go` under the `Start()` method. The following changes must be implemented:

### Step A: Update `controlplane.go` Imports
Ensure `os` is imported for handling socket file removals and permission modifications:
```go
import (
	"fmt"
	"log"
	"net"
	"os"
	// other imports...
)
```

### Step B: Bind Unix Socket in `Start()`
`kb-control-plane/internal/controlplane/controlplane.go` binds the gRPC server to a UDS via a dedicated `listenUnix` helper. The socket path defaults to `ipc.SocketGRPC` (`/run/kb/kba.sock`) and can be overridden with the `KB_GRPC_SOCKET` env var (used by tests and local dev). There is **no TCP fallback** — if the UDS bind fails, `Start()` returns an error:

```go
func (cp *ControlPlane) Start() error {
	// ...

	grpcSocketPath := os.Getenv("KB_GRPC_SOCKET")
	if grpcSocketPath == "" {
		grpcSocketPath = ipc.SocketGRPC
	}
	lis, err := listenUnix(grpcSocketPath)
	if err != nil {
		return fmt.Errorf("grpc uds listen: %w", err)
	}

	cp.grpc = grpc.NewServer()
	registerHealthService(cp.grpc, cp.healthServer)
	pb.RegisterKernelBorderlandsServer(cp.grpc, cp)

	go func() {
		log.Println("[KB] gRPC on unix://" + grpcSocketPath)
		if err := cp.grpc.Serve(lis); err != nil {
			log.Printf("[KB] grpc Serve exited: %v", err)
		}
	}()

	log.Println("[KB] Control plane ready")
	return nil
}

// listenUnix binds a UDS listener at path, clearing any stale socket file
// left behind by a previous run, and sets 0660 permissions.
func listenUnix(path string) (net.Listener, error) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("removing stale socket %s: %w", path, err)
	}
	lis, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o660); err != nil {
		lis.Close()
		return nil, fmt.Errorf("chmod socket %s: %w", path, err)
	}
	return lis, nil
}
```

### Step C: Clean Shutdown in `Stop()`
The socket file is unlinked when the control plane stops gracefully:

```go
func (cp *ControlPlane) Stop() {
	// ...
	cp.grpc.GracefulStop()
	grpcSocketPath := os.Getenv("KB_GRPC_SOCKET")
	if grpcSocketPath == "" {
		grpcSocketPath = ipc.SocketGRPC
	}
	os.Remove(grpcSocketPath) // best-effort cleanup so next start doesn't hit a stale file
	cp.store.Close()
	// ...
}
```

Any code that checks whether the gRPC service is reachable (e.g. dashboard health widgets) must dial the UDS path, not a TCP port — see `isSocketOpen` in `kb-control-plane/internal/controlplane/http.go`.

---

## 3. Impact & Dependency Checks
1. **Watchdog Connection (`kb-checker`)**: The Rust watchdog is configured to connect to `/run/kb/kba.sock`. Once this change is compiled, `kb-checker` will establish a connection immediately at boot-time Phase 2.
2. **Ray Agent Connection (`kbd-agent`)**: Ray nodes must be configured to pass UDS paths (`unix:///run/kb/kba.sock`) to their gRPC dial options.
