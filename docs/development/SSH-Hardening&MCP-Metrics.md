# Implementation Plan - Task 4: SSH Hardening & MCP Metrics

## Goal Description
Task 4 focuses on two areas:
1. **Control Plane SSH Hardening**: Add a hardened SSH service to `kbd` (the Control Plane daemon) responsible for authenticating remote operators via persistent host key + authorized public keys, allocating a PTY, and launching the `kb-tui` interface. SSH no longer lives inside `kb-tui`.
2. **MCP Metrics Integration**: Expose host/system statistics through the Model Context Protocol (MCP) server `kb.get_statistics` tool by querying `kbd` via gRPC.

---

## Architecture

SSH is a network-facing service and belongs to the daemon, not the UI. `kb-tui` is a pure remote operator interface driven over stdin/stdout and IPC/gRPC — it should have no knowledge of sockets, host keys, or authentication.

```
SSH Client
      │
      ▼
kbd
├── HTTP
├── gRPC
├── IPC
├── SSH   ← moved here
└── Policy
      │
      spawn
      ▼
Rust kb-tui
```

### Session Flow
```
Operator
  ssh kb@host
      ↓
  kbd
      ↓
  Validate host key
      ↓
  Validate authorized_keys
      ↓
  Allocate PTY
      ↓
  Launch kb-tui
      ↓
  Attach stdin/stdout
      ↓
  kb-tui
      ↓
  IPC/gRPC
      ↓
  kbd backend
```

---

## Proposed Changes

### 1. Control Plane & gRPC API (`kb-control-plane/`)

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

### 2. Control Plane SSH Service (`kb-control-plane/internal/ssh/`)

#### [NEW] Package layout
```
internal/
    ssh/
        auth.go       // authorized_keys parsing & validation
        hostkey.go    // persistent host key load/generate
        server.go      // wish server setup, listen/serve
        session.go     // PTY allocation, kb-tui process spawn, attach stdio
        config.go      // paths, addr, key policy
        README.md
```

Responsibilities:
* Load persistent host key (generate once if absent, never regenerate on restart)
* Validate authorized public keys (public-key auth only, no passwords)
* Run the Wish SSH server
* Allocate a PTY per session
* Manage session lifecycle (connect, resize, disconnect, logging)
* Spawn and attach the `kb-tui` binary as a subprocess, wiring its stdin/stdout to the SSH session

Hardening details to include in this section:
* Persistent host key stored at `/etc/kb/ssh_host_ed25519_key` (renamed — see naming note below), Ed25519
* `/etc/kb/authorized_keys` for authorized public keys, public-key auth only (no password fallback)
* Per-session PTY allocation
* Session logging (connect/disconnect, source IP, key fingerprint)
* Fallback to a local path only in dev, with a clear warning — production should hard-fail if `/etc/kb` isn't writable/readable rather than silently falling back

#### [MODIFY] `cmd/kbd/main.go`
Wire the SSH service into daemon startup alongside the other transports:
```go
func main() {
	cp := controlplane.New(...)

	go cp.StartHTTP()
	go cp.StartGRPC()
	go cp.StartIPC()

	if err := ssh.Start(cp); err != nil {
		log.Fatalf("failed to start SSH service: %v", err)
	}

	cp.Run()
}
```

---

### 3. `kb-op/kb-tui/` — plain Rust crate
```
kb-op/
    kb-tui/
        Cargo.toml
        src/
            main.rs
            app.rs
            ui/
            widgets/
            ipc/
```
`kb-tui` must not contain: Wish, `gliderlabs/ssh`, host key loading, `authorized_keys` handling, or any SSH configuration. Its responsibility is limited to:
* stdin / stdout / terminal resize handling
* IPC/gRPC calls to `kbd` for data

No network-facing code of any kind.

---

### 4. MCP Server & Metrics Gateway (`kb-op/kb-mcp/`)

#### [NEW] `kb-op/kb-mcp/main.go`
Entrypoint for the Model Context Protocol (MCP) server. Dials the Control Plane's gRPC socket and exposes the `kb.get_statistics` JSON-RPC tool. This component is independent of the SSH service.
```go
package main

import (
	"context"
	"encoding/json"
	"log"

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
	log.Println("MCP server starting...")
}
```

---

## Naming Note

The host key belongs to the SSH service provided by `kbd`, not to the TUI. Rename:
```
/etc/kb/tui_host_key
```
to
```
/etc/kb/ssh_host_ed25519_key
```
(or `/etc/kb/kbd_host_key`). This leaves room for future operator interfaces beyond `kb-tui` without implying the key is UI-specific.

---

## Verification Plan

### Automated Tests
Run `go test ./...` in `kb-control-plane` to ensure the new `GetSystemStats` RPC and the new `internal/ssh` package don't break existing code. Add unit tests for `internal/ssh`: host key load/persist, authorized_keys parsing, and rejection of unauthorized keys.

### Manual Verification
1. Run `make proto` inside `kb-control-plane` to regenerate Protobuf files.
2. Build `kbd` and confirm it starts HTTP, gRPC, IPC, and SSH services together.
3. Confirm the host key at `/etc/kb/ssh_host_ed25519_key` is generated once and persists across restarts (no MITM warning on reconnect).
4. Run `ssh kb@localhost` and confirm:
   ```
   kbd → SSH → validates key → launches kb-tui → Ratatui appears
   ```
5. Confirm an unauthorized public key is rejected.
6. Confirm `kb-op/kb-tui` builds as a plain Rust crate with no SSH/network dependencies.