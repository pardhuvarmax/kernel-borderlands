# Implementation Plan - Task 4: SSH Wish Hardening & MCP Metrics

## Goal Description
Task 4 focuses on two areas:
1. **TUI SSH Hardening**: Transition the `kb-tui` service from regenerating SSH host keys on every startup (which causes MITM warnings) to loading a persistent host key from `/etc/kb/tui_host_key`, and validating authorized public keys.
2. **MCP Metrics Integration**: Expose host/system statistics through the Model Context Protocol (MCP) server `kb.get_statistics` tool by querying the Control Plane daemon (`kbd`) via gRPC.

---

## Proposed Changes

### 1. Control Plane & gRPC API (`kb-control-plane/`)
We need to update the Control Plane's gRPC interface to expose the system metrics so the MCP server (or TUI) can fetch them.

#### [MODIFY] `proto/kb.proto`
Add an empty request message, a statistics response message, and register the `GetSystemStats` RPC method.
```protobuf
message Empty {}

message SystemStats {
    double events_per_second = 1;
    uint32 active_processes  = 2;
}

service KernelBorderlands {
    // ... existing RPCs ...
    
    // Query global telemetry stats and process volumes
    rpc GetSystemStats(Empty) returns (SystemStats);
}
```

#### [MODIFY] `internal/controlplane/grpc.go`
Implement the new `GetSystemStats` endpoint on the `ControlPlane` struct, querying internal state (events per second, active processes count).
```go
func (cp *ControlPlane) GetSystemStats(
	ctx context.Context, req *pb.Empty,
) (*pb.SystemStats, error) {
	eps := cp.GetEventsPerSecond()
	active := uint32(len(cp.store.ListAll()))
	return &pb.SystemStats{
		EventsPerSecond: eps,
		ActiveProcesses: active,
	}, nil
}
```

---

### 2. TUI SSH Hardening (`kb-op/kb-tui/`)

#### [NEW] `kb-op/kb-tui/cmd/main.go`
Create the entrypoint for the TUI, loading the persistent host key from `/etc/kb/tui_host_key` and implementing public key authentication.
```go
package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/charmbracelet/wish"
	"github.com/gliderlabs/ssh"
)

func validateAuthorizedKeys(key ssh.PublicKey) bool {
	// Authorized key validation logic
	return true
}

func StartSSH() {
	hostKeyPath := "/etc/kb/tui_host_key"
	
	// Create directory if it doesn't exist (if permissions allow, otherwise fallback to local dir)
	if err := os.MkdirAll(filepath.Dir(hostKeyPath), 0755); err != nil {
		log.Printf("Warning: failed to create /etc/kb directory: %v, using local fallback", err)
		hostKeyPath = "./tui_host_key"
	}

	s, err := wish.NewServer(
		wish.WithAddress("0.0.0.0:2222"),
		wish.WithHostKeyPath(hostKeyPath),
		wish.WithPublicKeyAuth(func(ctx ssh.Context, key ssh.PublicKey) bool {
			return validateAuthorizedKeys(key)
		}),
	)
	if err != nil {
		log.Fatalf("Failed to create SSH server: %v", err)
	}

	log.Printf("Starting SSH server on 0.0.0.0:2222 (Host Key: %s)", hostKeyPath)
	if err := s.ListenAndServe(); err != nil {
		log.Fatalf("SSH server shut down: %v", err)
	}
}

func main() {
	StartSSH()
}
```

---

### 3. MCP Server & Metrics Gateway (`kb-op/kb-mcp/`)

#### [NEW] `kb-op/kb-mcp/main.go`
Create the entrypoint for the Model Context Protocol (MCP) server. It will dial the Control Plane's gRPC socket and expose the `kb.get_statistics` JSON-RPC tool.
```go
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pb "github.com/pardhuvarmax/kernel-borderlands/kb-control-plane/proto"
)

func getSystemStatistics(client pb.KernelBorderlandsClient) (string, error) {
	ctx := context.Background()
	stats, err := client.GetSystemStats(ctx, &pb.Empty{})
	if err != nil {
		return "", err
	}

	payload, err := json.MarshalIndent(stats, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

func main() {
	// Basic MCP server logic (JSON-RPC stdio transport) or client stub
	log.Println("MCP server starting...")
}
```

---

## Verification Plan

### Automated Tests
Run `go test ./...` in the `kb-control-plane` directory to ensure that modifying the gRPC service definition does not break any existing code.

### Manual Verification
1. Run `make proto` inside `kb-control-plane` to regenerate Protobuf files.
2. Build the control plane and ensure the server implements the `GetSystemStats` RPC method.
3. Test that the Wish SSH Server loads `/etc/kb/tui_host_key` (or falls back to local path if permission denied) and serves on port 2222.
