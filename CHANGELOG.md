# Changelog

All notable changes to the **Kernel Borderlands** project are documented below.

---

## [Unreleased] - 2026-07-14

### Added
- **Build & Test Scripts (`kb-core`)**: Added helper utilities `build.sh`, `clean.sh`, `test.sh`, and `attach.sh` for simplified operations.
- **Git Authorship Aliases**: Added system-wide bash aliases to `/etc/bash.bashrc` to handle multi-contributor commits cleanly.

---

## Major Subsystem Milestones (Chronological History)

### July 2026

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
