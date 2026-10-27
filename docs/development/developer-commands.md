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
  `/etc/kb/sshd_kb-operator.conf` config (not `sshd_config.d`, see the correction there) and `sshd@kb-operator.service` unit.
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
  cd kb-op/kbctl && go build -o kbctl .   # several files now; `go build main.go` fails
  ```
- **Reload Policies**:
  ```bash
  ./kbctl policy reload
  ```

### I. Packaging, install and real-host testing
- **Build everything** (system toolchains on `PATH`, e.g. `PATH=/usr/local/bin:/usr/bin`; a Nix `clang` cannot see `/usr/include/bpf`):
  ```bash
  make build            # kb-core sensor, kbd, kb-checker, kbctl, mcp-server, dashboard + kbopd
  ```
- **Ubuntu `.deb`** (build on the target distro; binaries link the build host's glibc):
  ```bash
  packaging/deb/build-deb.sh           # -> dist/kernel-borderlands_0.1.0_amd64.deb
  ```
- **Arch package**:
  ```bash
  cd packaging/arch && makepkg -f      # -> kernel-borderlands-0.1.0-1-x86_64.pkg.tar.zst
  ```
- **Install, start, demo, uninstall** (full runbook with expected output: `latex/field-manual/`, Chapter "Demonstration Runbook"):
  ```bash
  sudo apt install ./kernel-borderlands_0.1.0_amd64.deb      # or: sudo pacman -U kernel-borderlands-*.pkg.tar.zst
  sudo kbctl ssh add-key ~/.ssh/id_ed25519.pub && sudo kbctl up
  kbctl status && kbctl dashboard open && kbctl ssh connect
  sudo kbctl down && sudo apt purge kernel-borderlands       # or: sudo pacman -R kernel-borderlands
  ```
- **Real-host acceptance scripts** (Ubuntu VM, need sudo and a TTY): `ssh -t HOST 'bash ~/kbinstaller.sh'` and `ssh -t HOST 'bash ~/kbuninstaller.sh [--remove-package]'`, sources in `packaging/vm-test/`.
- **Build the field manuals** (LuaLaTeX): `cd latex/field-manual && make` -> `build/KB-Field-Manual-{Arch,Ubuntu}.pdf`; `make help` regenerates the CLI reference from the binaries.

