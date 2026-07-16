# Changelog

All notable changes to the **Kernel Borderlands** project are documented below.

---

## [Unreleased] - 2026-07-16

### Added
- **AADS Real UDS Verification Guide & Script (`docs/development/control-aads`)**: Added a guide and helper Python script `tests/verify_real_connection.py` to run live connection integration tests between the Python AADS client and the Go control plane. [PardhuVarma]
- **AADS gRPC-over-UDS Client & Ray Actors (`kb-aads`)**: Implemented the Python gRPC client in `comms/grpc_client.py` covering all `kb.proto` methods, created a UDS socket integration test suite with `pytest`, decorated base agents to leverage Ray remote actors, and structured the JJE consensus quorum model. [PardhuVarma]
- **AADS Development Plan (`docs/development/control-aads`)**: Created the comprehensive roadmap and architectural blueprint for migrating python agents to Ray remote actors, implementing JJE consensus quorum, integrating gRPC-over-UDS communications, and configuring Ray RLlib multi-agent reinforcement learning. [PardhuVarma]
- **Process Exit Lifecycle (`kb-control-plane`)**: Implemented packet routing and decoding for `MsgTypeProcessExit` (`4`) to immediately flush stale L1 memory cache and L2 SQLite process records upon process termination, preventing PID reuse vulnerabilities. [Tejaswini4119]
- **Process Exit Unit Tests (`kb-control-plane`)**: Added unit and integration tests in `controlplane_test.go` and `wire_test.go` to verify cache eviction and SQL deletion. [Tejaswini4119]
- **SSH Hardening & MCP Specs (`docs`)**: Added Task 4 implementation plan details for SSH Wish hardening and MCP metrics integration. [Tejaswini4119]
- **eBPF Rate Limiting (`kb-core`)**: Implemented hybrid BPF token buckets using Task Local Storage and LRU Hash Maps. 
- **Deep Resource Isolation (`kb-core`)**: Upgraded rate limiting to track limits by `PID + Resource ID` (e.g., Destination IP, Syscall ID) to prevent smoke-grenade sensor evasion.
- **Telemetry Batching (`kb-core`)**: Added `KB_EVT_DROPPED_TELEMETRY` event to accurately aggregate and report dropped payloads to the userspace behavior engine.
- **Rate Limit Isolation Test (`kb-core`)**: Added `tests/isolation_test.py` to test BPF token bucket overload boundaries.
- **Build & Test Scripts (`kb-core`)**: Added helper utilities `build.sh`, `clean.sh`, `test.sh`, and `attach.sh` for simplified operations.
- **Git Authorship Aliases**: Added system-wide bash aliases to `/etc/bash.bashrc` to handle multi-contributor commits cleanly.
- **IPC Restore Test (`kb-core`)**: Added dedicated python integration test script `kb-core/tests/test_restore_ipc.py` to mock control plane containment commands.

### Changed
- **TUI Architecture Updates (`kb-op/kb-tui`)**: Updated `kb-tui` documentation to reflect transition to Ratatui (Rust) and delegation of SSH handling/authentication to the control plane daemon (`kbd`). [PardhuVarma]
- **SSH Hardening Architecture Spec (`docs`)**: Refactored the Task 4 SSH Hardening design spec to move the network-facing SSH server into `kbd` (control plane daemon) and make `kb-tui` a pure subprocess driven over PTY stdin/stdout. [Tejaswini4119]
- **Containment Restore path correctness (`kb-core`)**: Implemented return check for `bpf_map_delete_elem` and `bpf_map_update_elem` in `kbd_sensor.c`, logging deletion/update failures to stderr.
- **Bounded logging outputs (`kb-core`)**: Bounded `cmd->reason` string printing to 64 bytes (`%.64s`) to avoid out-of-bound memory reads when logs print non-null-terminated reason strings.
- **LSM BPF Hook Verifications (`kb-core`)**: Modified LSM socket hook return values (`kb_lsm_socket_connect`, `kb_lsm_socket_bind`, `kb_lsm_file_mprotect`) in `kbd_sensor.bpf.c` to return `-13` (`-EACCES`) instead of `-1` to fix modern kernel verifier rejection.

### Removed 
- **Kafka Removal in AADS Subsystem (kb-aads/)**: removed kafka legacy code to implement low latency native uds communications fr inter-agent, and ray clusters.

---

## Major Subsystem Milestones (Chronological History)

### July 2026

*   **2026-07-16** - AADS gRPC-over-UDS client, UDS test suite, Ray remote actor base agents, JJE consensus, real connection verification script, and development plan (*PardhuVarma*)
*   **2026-07-15** - process exit lifecycle implementation, cache flushes, unit tests, and refactored SSH daemon-side architecture spec (*Tejaswini*); updated TUI README for Ratatui and kbd SSH delegation (*PardhuVarma*)
*   **2026-07-14** - eBPF token bucket rate limiting, telemetry batching, and deep resource isolation (*PardhuVarma*)
*   **2026-07-14** - gap work implementation, LSM hook return corrections & IPC restore tests (*PardhuVarma*)
*   **2026-07-14** - readme updates (*Rupa Karedla*)
*   **2026-07-13** - git authorship documentation updates (*PardhuVarma*)
*   **2026-07-13** - Controlplane updates (*Tejaswini*)
*   **2026-07-13** - CPM, CWP & Gap Fixation Updates (*PardhuVarma*)
*   **2026-07-11** - `kb-control-plane`: wire IPC listener, enforcer construction, Contain() call sites (*Tejaswini*)
*   **2026-07-11** - `kb-core`: containment restore and LSM enforcement coverage (*PardhuVarma*)
*   **2026-07-11** - `kb-core` sensor: autoload for TLS/SSL uprobes to resolve attachment failures (*PardhuVarma*)
*   **2026-07-11** - `kb-control-plane`: refined isProcessRunning argument matching to prevent false positives (*Tejaswini*)
*   **2026-07-11** - `kb-control-plane`: normalized raw scoring values for HTTP/SSE feeds (*Tejaswini*)
*   **2026-07-11** - `kb-dashboard`: dynamic health indicators and performance metrics from daemon (*Rupa Karedla*)
*   **2026-07-11** - `kb-dashboard`: Redesigned professional SOC console with sidebar, health panel, alert feed, and audit terminal (*Rupa Karedla*)
*   **2026-07-11** - `kb-dashboard`: Initialized Vite-React-TypeScript dashboard with premium security telemetry visualization (*Rupa Karedla*)
*   **2026-07-09** - `kb-checker`: removed Apache Kafka references in favor of ZeroMQ and Ray IPC (*Karthik*)
*   **2026-07-09** - `kb-checker`: implement hard fallback containment locks in report recovery (*PardhuVarma*)
*   **2026-07-09** - `kb-checker`: integrate systemd service controls in recovery (*PardhuVarma*)
*   **2026-07-09** - `docs`: added Secure Boot-up Tampering Containment and Workload Gating Section (*PardhuVarma*)
*   **2026-07-08** - `kb-checker`: single-instance PID locking and signal cleanup (*PardhuVarma*)
*   **2026-07-08** - `kb-checker`: eBPF hook performance latency monitoring (*PardhuVarma*)
*   **2026-07-08** - `kb-checker`: self-healing BPF map state integrity audits (*PardhuVarma*)
*   **2026-07-08** - `kb-checker`: dynamic SHA-256 eBPF bytecode instructions hashing (*PardhuVarma*)
*   **2026-07-08** - `kb-checker`: modularized safety checker and status gRPC server over Unix Domain Sockets (*PardhuVarma*)
*   **2026-07-08** - `kb-checker`: Rust safety daemon validation loops and gRPC/REST clients (*PardhuVarma*)
*   **2026-07-08** - `kb-core`: eBPF tasks for containment feedback loops and exit events (*PardhuVarma*)
*   **2026-07-07** - `kb-op`: Integrated `kb-mcp` subsystem tool suite for operators (*PardhuVarma*)
*   **2026-07-07** - `docs`: eBPF event rate limiting design specifications (*PardhuVarma*)
*   **2026-07-06** - `kb-core` & `kb-control-plane`: Integrated BPF LSM, behavior state machine, TLS uprobes, and fixed L2 DB race (*PardhuVarma & Tejaswini*)
*   **2026-07-06** - `kb-core` & `kb-control-plane`: Integrated BPF LSM, behavior state machine, TLS uprobes, and fixed L2 DB race (*PardhuVarma & Tejaswini*)
*   **2026-07-04** - `kb-control-plane`: SQLite3 database checks, core socket fallbacks, and major Go wiring updates (*Tejaswini & PardhuVarma*)
*   **2026-07-03** - `kb-core`: eBPF scoring engine (`kb_scoring.c/.h`) and Unix socket streaming (`kb_bridge.c/.h`) (*PardhuVarma*)
*   **2026-07-01** - `docs`: Rupa On-boarding and team info update (*Rupa Karedla & PardhuVarma*)
*   **2026-07-01** - Userspace reorganization and build improvements (*PardhuVarma*)

### June 2026

*   **2026-06-26** - `kb-control-plane`: Protofile definition and daemon initialization (*Tejaswini*)
*   **2026-06-26** - `kb-checker`: Kafka topics and communication setup (*Karthik*)
*   **2026-06-26** - `kb-core`: Hook-2 syscall tracking (*PardhuVarma*)
*   **2026-06-26** - Karthik onboarding to the kernel-borderlands team (*Karthik & PardhuVarma*)
*   **2026-06-25** - `kb-core`: CO-RE & Cross Kernel Portability specs (*PardhuVarma*)
*   **2026-06-25** - `kb-aads`: Swarm Initial Setup (*Karthik*)
*   **2026-06-25** - `kb-core`: Initial eBPF tracepoints program (*PardhuVarma*)
*   **2026-06-25** - Tejaswini onboarding to the kernel-borderlands team (*Tejaswini & PardhuVarma*)
*   **2026-06-19** - Documentation for hook points and monitoring strategies (*PardhuVarma*)
*   **2026-06-11** - AADS Swarm technical requirements (*PardhuVarma*)

### May 2026

*   **2026-05-02** - Initial project repository setup, initial README, and project description (*PardhuVarma*)

---

## Contributor Breakdown

### Pardhu Varma (`PardhuVarma Konduru`)
- Lead developer of eBPF instrumentation (`kb-core`), including LSM hooks, tracing, and dynamic skeletons.
- Architected the Rust safety watchdog (`kb-checker`).
- Set up project specs, boot sequences, and collaborative roadmaps.

### Rupa Karedla (`Rupakaredla`)
- Architected and built the React-TypeScript SOC Dashboard (`kb-dashboard`).
- Integrated HTTP telemetry and SSE feeds.
- Contributed to userspace documentation.

### Tejaswini (`Tejaswini4119`)
- Built the Go daemon control plane (`kb-control-plane`) and CGO bindings.
- Configured SQLite3 local storage and gRPC interfaces.
- Implemented event normalizations.

### Karthik (`Karthik21002`)
- Researched agent defense swarm (`kb-aads`).
- Configured ZeroMQ, Kafka topics, and Ray IPC.
