# Go Control Plane Command Entrypoint (`kb-control-plane/cmd/`)

This directory contains the main package entrypoints for compiling the Go Control Plane binaries.

---

## 📂 Executables

### 1. `kbd/`
* **Path**: `cmd/kbd/main.go`
* **Purpose**: Compiles into the main userspace control plane daemon (`kbd`).
* **Roles**:
  * Loads database files and policy YAML files.
  * Starts two C-to-Go IPC Unix Sockets: `/run/kb/kbd.sock` (telemetry, sensor → Go) and `/run/kb/kbct.sock` (control pushes — containment commands, sensitive-path pushes — Go → sensor). Split so a telemetry-volume burst can never stall or kill containment delivery; see `docs/development/core-control/control-plane-catalog.md` §5.3.
  * Binds and serves the gRPC server on the Unix Domain Socket (`/run/kb/kba.sock`).
  * Listens for termination signals and handles database closing.

---

## 🛠️ Build Commands

To build the executable, run:
```bash
cd kb-control-plane
go build -o bin/kbd cmd/kbd/main.go
```
