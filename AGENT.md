# AGENT.md — Agent Operational Reference & Architectural Invariants

This document serves as the primary operational context and state manual for AI agentic assistants (e.g., Antigravity, agy, Claude, Cursor) working inside the Kernel Borderlands codebase.

---

## 1. Environment & Credential Context

- **Test Ingestion Constraint**: Never pass or encode passwords inside test arguments or prompts (specifically in `test_all_hooks.sh`). Test routines must run passwordlessly or prompt with short timeouts that fall back gracefully rather than hanging.
- **Git Tracking Exclusions**: Do NOT stage or commit the local agent work files under [docs/AGENT_WORK/](file:///home/emergence/Desktop/kernel-borderlands/docs/AGENT_WORK). These files must remain local to the development workspace.
- **Master Specification**: The authoritative technical reference for all subsystems resides in [docs/project/kernel_borderlands_specification.md](file:///home/emergence/Desktop/kernel-borderlands/docs/project/kernel_borderlands_specification.md). Keep this file's length at or above 1500 lines to preserve implementation guides.

---

## 2. Codebase Truths & Architectural Invariants

Always adhere to these engineering invariants. Any code change violating them is incorrect:

### A. Execution Zone Transitions
- **State Machine Rules**: Transitions between execution zones (`SAFE` $\to$ `SUSPICIOUS` $\to$ `BORDERLANDS`) are managed exclusively by pattern-sequence checks within the userspace Behavior State Machine.
- **Advisory Scoring**: The Behavioral Risk Score ($S_t$) calculated via Exponential Moving Average (EMA) is **strictly advisory**. Do NOT write logic that triggers zone transitions based on risk score thresholds.

### B. Control Plane Database Cache Topology
- **Cache Topology**: The control plane uses a two-tiered memory architecture:
  - **L1 Cache**: A thread-safe `sync.Map` in Go to serve read operations. Do NOT refer to it as a "lock-free Go heap cache."
  - **L2 Database**: SQLite engine running with Write-Ahead Logging (`WAL`) enabled, operating as an asynchronous write-behind persistence layer.
- **Sync Barrier on Exit**: The Go control plane uses a synchronization channel barrier (`l2Done chan struct{}`) in the L2 worker to guarantee that all pending logs in the write-behind pipe are fully flushed to SQLite before the connection closes on daemon teardown.

### C. Socket IPC & Privilege Isolation
- **IPC Interface**: Communication between the native userspace bridge and the Go control plane is over `/tmp/kbd.sock`.
- **Privilege Separation**: The UDS socket must reside in `/tmp/` rather than `/var/run/` to enable the Go control plane daemon to run without root privileges, while remaining writable by the root-level eBPF userspace bridge sensor using `0666` permissions.

---

## 3. Standard Verification Workflows

Before declaring any task complete, perform these sanity checks:
1. Ensure the eBPF hooks build successfully (`cd kb-core && make`).
2. Run safety/integrity diagnostics (`cd kb-checker && cargo test`).
3. Verify that changes to the landing page [docs/index.html](file:///home/emergence/Desktop/kernel-borderlands/docs/index.html) do not introduce layout shifts or break compatibility with simple card formats.
4. Run `git status` to ensure `docs/AGENT_WORK/` remains untracked and that all files are committed cleanly.
