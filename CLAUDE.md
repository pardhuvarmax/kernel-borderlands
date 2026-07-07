# CLAUDE.md — Developer Reference & Codebase Style Guide

This document defines standard build, run, test, and style conventions for the Kernel Borderlands repository. Use this reference to ensure consistent code styling and component interaction patterns across all subsystems.

---

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
- **Run Daemon (Accesses `/run/kb/kbd.sock`)**:
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
- **Run Self-Diagnostics**:
  ```bash
  ./target/release/kb-checker service --all
  ```
- **Run Unit Tests**:
  ```bash
  cargo test
  ```

### D. `kb-tui` (SSH Terminal Dashboard)
- **Build Console Binary**:
  ```bash
  cd kb-op/kb-tui && go build -o kb-tui cmd/main.go
  ```
- **Run Console Locally**:
  ```bash
  cd kb-op/kb-tui && go run cmd/main.go
  ```
- **SSH into Console (Running on Port 2222)**:
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

---

## 2. Codebase Style & Implementation Guidelines

### A. C & eBPF Guidelines
- **Kernel Conventions**: Follow Linux kernel coding style. Indent with tabs.
- **eBPF Relocations**: Use CO-RE (Compile Once – Run Everywhere) helpers (`bpf_core_read`, etc.) to guarantee compatibility.
- **LSM Blocks**: Implement `SEC("lsm/file_open")` return blocks correctly using `-EACCES` for access restriction.
- **Map Security**: Set strict permissions on ring buffers and eBPF maps. Prefer `bpf_ringbuf` for telemetry streams to handle high event rates.

### B. Go Guidelines
- **Format**: Always run `gofmt` and `goimports` before committing.
- **Cache Pattern**: Keep the L1 cache as a thread-safe `sync.Map` for read paths, backing it up with an asynchronous SQLite WAL L2 database.
- **Shutdown Safety**: Use the teardown synchronization channel barrier `l2Done chan struct{}` in write-behind workers to ensure SQLite database flushes complete prior to daemon termination.
- **Privilege Separation**: Keep sockets at `/run/kb/kbd.sock` rather than root-only directories, ensuring the Go daemon can run with non-root permissions while root-level eBPF logs are piped in.

### C. Rust Guidelines
- **Formatting**: Format using standard `cargo fmt` guidelines.
- **Safety**: Prefer safe, idiomatic Rust. Restrict the usage of `unsafe` blocks to foreign interfaces or direct kernel register mappings.
- **Error Handling**: Use `Result` and structured errors. Avoid `unwrap()` and `expect()` in system critical loops.

### D. Python Guidelines
- **Standards**: Adhere to PEP 8 standards.
- **Concurrency**: Use async ZeroMQ message loop hooks. Minimize polling loops to maintain low CPU overhead.

### E. UI & Styling Guidelines
- **Styles**: Keep styling focused in index.css. Avoid adding styling configurations inside layouts that create rendering latency or layout shifts.
- **Animations**: Prefer GPU-accelerated transition properties (`transform: scale3d`, `opacity`) over height changes to prevent grid layout repaints.
