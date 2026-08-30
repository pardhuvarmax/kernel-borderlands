# Developer Commands

This document contains the most commonly used build, test, and runtime commands for each Kernel Borderlands subsystem.

## 1. Subsystem Commands Quick Reference

### A. `kb-core` (Kernel eBPF & Userspace Loader)
- **Compile eBPF Skels & Userspace Loader**:
  ```bash
  cd kb-core && make
  ```
- **Run eBPF Loader Daemon (Requires Root)**:
  ```bash
  sudo ./build/kbd_sensor
  ```
- **Run Telemetry Tests**:
  ```bash
  cd kb-core && ./tests/test_all_hooks.sh
  ```
  *(Note: Never pass sudo passwords directly to this test script).*

### B. `kb-control-plane` (Go Core Daemon)
- **Build Core Daemon**:
  ```bash
  cd kb-control-plane && go build -o bin/kbd cmd/kbd/main.go
  ```
- **Run Daemon (binds `/run/kb/kbd.sock` telemetry + `/run/kb/kbct.sock` control + `/run/kb/kba.sock` gRPC)**:
  ```bash
  go run cmd/kbd/main.go
  ```
- **Test Ingestion & Auditing**:
  ```bash
  go test ./...
  ```

### C. `kb-checker` (Rust Safety & Integrity Layer)
- **Compile Release Crate**:
  ```bash
  cd kb-checker && cargo build --release
  ```
- **Execute Safety & Integrity Checks**:
  ```bash
  ./target/release/kb-checker monitor --all
  ```
- **Run Unit Tests**:
  ```bash
  cargo test
  ```

### D. `kb-tui` (SSH Terminal Dashboard)
`kb-tui` is a Rust/Cargo binary (`ratatui`), not Go — the commands below were corrected
from an earlier `go build`/`cmd/main.go` version that didn't match this crate's actual
layout (no `cmd/` directory, no `main.go`; see `kb-op/kb-tui/Cargo.toml`).
- **Build Console Binary**:
  ```bash
  cd kb-op/kb-tui && cargo build --release   # output: target/release/kb-tui
  ```
- **Run Console Locally**:
  ```bash
  cd kb-op/kb-tui && cargo run
  ```
- **SSH into Console (Running on Port 2222)**: as of the OpenSSH migration
  (`docs/development/core-control/control-plane-catalog.md` §2.11), port 2222 is served by a
  real, OS-managed `sshd` instance with `ForceCommand /usr/local/bin/kb-tui` — `kbd` no longer
  hosts an in-process SSH server. See `docs/architecture/boot_sequence_spec.md` §3 for the
  `sshd_config.d` drop-in and `sshd@kb-operator.service` unit.
  ```bash
  ssh operator@localhost -p 2222
  ```

### E. `kb-dashboard` (Vite + React Web App)
- **Install Dependencies**:
  ```bash
  cd kb-op/kb-dashboard && npm install
  ```
- **Run Dev Server (Port 5173)**:
  ```bash
  cd kb-op/kb-dashboard && npm run dev
  ```
- **Compile Production Assets**:
  ```bash
  npm run build
  ```

### F. `kb-aads` (Python Swarm)
- **Run Swarm Daemon**:
  ```bash
  cd kb-aads && python main.py
  ```
- **Execute Agent Tests**:
  ```bash
  pytest
  ```

### G. `kb-mcp` (Model Context Protocol Host)
- **Build MCP Server**:
  ```bash
  cd kb-op/kb-mcp && go build -o kb-mcp main.go
  ```
- **Run MCP Server**:
  ```bash
  cd kb-op/kb-mcp && ./kb-mcp
  ```

### H. `kbctl` (Command Line Client)
- **Build CLI Client**:
  ```bash
  cd kb-op/kbctl && go build -o kbctl main.go
  ```
- **Reload Policies**:
  ```bash
  ./kbctl policy reload
  ```
