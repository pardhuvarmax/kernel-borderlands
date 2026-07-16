# Changelog

All notable changes to the **Kernel Borderlands** project are documented below.

---

## [d8c6665] - 2026-07-17

### Added
- **TUI demonstration media (`kb-op/kb-tui/media/`)**: Added `kbtui.gif` and `kbtui.mp4` showing full demonstrations of the new Rust-based `kb-tui` console in action. [PardhuVarma]
- **Verification suite upgrade (`kb-core/tests/test_all_hooks.sh`)**: Refactored the validation script to trigger sequential, multi-stage attack chains (Privilege & Credential, Memory Injection, and C2 Connections) within single processes to test end-to-end `BORDERLANDS` and `COMPROMISED` alert streams. [PardhuVarma]
- **kb-tui rebuilt as a real operator console (`kb-op/kb-tui`)**: Replaced the static ratatui demo screen with a multi-panel console (Processes / Alerts / Agent Activity / Query Console tabs), wired to `kbd`'s `KernelBorderlands` gRPC service over `/run/kb/kba.sock` (tonic + `kb.proto`), with zone-colored process table, filtering, containment action modal, live alert feed, and a typed query-console mini-language. Falls back to a clearly-bannered offline/demo mode with synthetic data if `kbd` is unreachable. [PardhuVarma]
- **Operator-configurable sensitive-path list (`config/policy.yaml`, `kb-control-plane`, `kb-core`)**: Added a `sensitive_paths` key to `policy.yaml`, validated by a new `internal/policy` check (absolute path, fits the 64-byte BPF key, not bare `/`, dedup, capacity-checked against the map's 64-entry limit), pushed to `kbd_sensor` over a new wire message (`KBWireMsgSensitivePaths`, `msg_type=6`, `internal/ipc/sensitive_paths.go`) the moment it connects, and merged into the live `kb_sensitive_paths` BPF map on top of the compiled-in floor. Additive only — the floor can never be narrowed via config. Takes effect on `kbd_sensor` (re)connect, not a live reload. [PardhuVarma]
- **`kb-core/scratchpad/` manual verification scripts**: `run-sensor.sh` (start/restart `kbd_sensor` with logging) and `inspect-bpf-state.sh` (`bpftool`-based dump of live LSM program attachment and `kb_sensitive_paths`/`contained_pids_map` state) — root-requiring, interactive, not part of CI; written specifically because the bugs below were only caught by checking live kernel state, not by build success. [PardhuVarma]
- **AADS Real UDS Verification Guide & Script (`docs/development/control-aads`)**: Added a guide and helper Python script `tests/verify_real_connection.py` to run live connection integration tests between the Python AADS client and the Go control plane. [Karthik]
- **AADS gRPC-over-UDS Client & Ray Actors (`kb-aads`)**: Implemented the Python gRPC client in `comms/grpc_client.py` covering all `kb.proto` methods, created a UDS socket integration test suite with `pytest`, decorated base agents to leverage Ray remote actors, and structured the JJE consensus quorum model. [Karthik]
- **AADS Development Plan (`docs/development/control-aads`)**: Created the comprehensive roadmap and architectural blueprint for migrating python agents to Ray remote actors, implementing JJE consensus quorum, integrating gRPC-over-UDS communications, configuring Ray RLlib multi-agent reinforcement learning, and enabling Ray mTLS cluster encryption. [PardhuVarma]
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
- **kb-tui declared canonical as Rust/ratatui, not Go (`kb-op/kb-tui`, `kb-op/README.md`, `docs/specifications/operator_interfaces_spec.md`, wiki)**: These four sources disagreed on kb-tui's language/architecture (Go+Bubble Tea+Wish vs. the Rust+ratatui code actually in the repo). Reconciled all of them to Rust/ratatui/tonic, SSH handled entirely by `kbd` (PTY spawn), `kb-tui` talking gRPC over `/run/kb/kba.sock`. [PardhuVarma]
- **Compiled-in LSM sensitive-path floor narrowed (`kb-core/userspace/sensor/kbd_sensor.c`)**: Changed from `{/etc/shadow, /etc/passwd, /etc/sudoers, /root/}` to `{/etc/shadow, /etc/sudoers, /root/.ssh/}`. Dropped `/etc/passwd` — it holds no credential material on a shadow-password system and is opened by nearly every UID-resolving tool (`ls -l`, `id`, `ps`, `sudo`, `ssh`, ...); passive `KB_EV_PASSWD_ACCESS` scoring is unaffected. Narrowed `/root/` to `/root/.ssh/` (the actual credential material, not root's whole home directory). [PardhuVarma]
- **`kb_lsm_file_open` sensitive-path blocking changed from unconditional to containment-gated (`kb-core/ebpf/kbd_sensor.bpf.c`)**: The hard `-EACCES` block now only applies to a process already under operator containment at level ≥2 (Seccomp), matching the containment-level model every other LSM hook in the file already follows (`kb_lsm_bprm_check`, `kb_lsm_socket_connect`, `kb_lsm_socket_bind`, `kb_lsm_file_mprotect`). Passive detection (`kb_handle_openat`'s evidence flags) is unaffected and still fires for every process regardless of containment. **See the Incident section below — this change exists because the previous unconditional version locked `sudo`/PAM out of a live VM.** [PardhuVarma]
- **`MsgTypeContainmentCmd` changed `3` → `5` (`kb-control-plane/internal/ipc/types.go`)**: Now matches the C side's `KB_WIRE_MSG_CONTAINMENT_CMD` (`kb_bridge.h`). See Fixed below — this was a real, previously-shipped bug, not a new choice. [PardhuVarma]
- **`connect_once()` now sets a 2s `SO_RCVTIMEO` (`kb-core/userspace/bridge/kb_bridge.c`)**: The sensor's connect-time blocking reads (rules, sensitive-paths) now fail fast into their documented "use compiled-in defaults" fallback instead of blocking forever. [PardhuVarma]
- **TUI Architecture Updates (`kb-op/kb-tui`)**: Updated `kb-tui` documentation to reflect transition to Ratatui (Rust) and delegation of SSH handling/authentication to the control plane daemon (`kbd`). [PardhuVarma]
- **SSH Hardening Architecture Spec (`docs`)**: Refactored the Task 4 SSH Hardening design spec to move the network-facing SSH server into `kbd` (control plane daemon) and make `kb-tui` a pure subprocess driven over PTY stdin/stdout. [Tejaswini4119]
- **Containment Restore path correctness (`kb-core`)**: Implemented return check for `bpf_map_delete_elem` and `bpf_map_update_elem` in `kbd_sensor.c`, logging deletion/update failures to stderr.
- **Bounded logging outputs (`kb-core`)**: Bounded `cmd->reason` string printing to 64 bytes (`%.64s`) to avoid out-of-bound memory reads when logs print non-null-terminated reason strings.
- **LSM BPF Hook Verifications (`kb-core`)**: Modified LSM socket hook return values (`kb_lsm_socket_connect`, `kb_lsm_socket_bind`, `kb_lsm_file_mprotect`) in `kbd_sensor.bpf.c` to return `-13` (`-EACCES`) instead of `-1` to fix modern kernel verifier rejection.

### Fixed
- **`kbd_sensor` hung forever at startup whenever `kbd` was reachable (`kb-core/userspace/sensor/kbd_sensor.c`)**: `read_rules_from_bridge()` did a blocking `read()` with no timeout, waiting for a rules frame that `kb-control-plane`'s production code (`SendRulesPayload`) never actually sends (it's only invoked from a test). The sensor would never reach eBPF loading. Fixed via the `SO_RCVTIMEO` change above. [PardhuVarma]
- **The `sensitive_paths` wire frame was silently discarded before the new reader ever saw it (`kb-core/userspace/sensor/kbd_sensor.c`)**: `read_rules_from_bridge()` blindly consumes whatever frame arrives next on the wire, regardless of its real `msg_type` — and since `kbd` sends the sensitive-paths push (the only frame actually sent at connect time) before the sensor gets around to reading for it, the rules reader ate it, saw a mismatched `msg_type`, and discarded it, leaving nothing for `read_sensitive_paths_from_bridge()` to read later. Fixed with a stash-and-reuse mechanism: `read_rules_from_bridge()` now stashes a non-rules frame it doesn't recognize instead of freeing it, and `read_sensitive_paths_from_bridge()` checks that stash first before attempting a fresh read. [PardhuVarma]
- **The LSM sensitive-path block had never actually been enforcing, despite being documented as "loaded & active" (`kb-core/ebpf/kbd_sensor.bpf.c`)**: `bpf_d_path()` writes a NUL-terminated path into `path_buf` but doesn't guarantee the buffer's tail past the terminator is zeroed, while `kb_sensitive_paths`' `bpf_map_lookup_elem` compares the full fixed-size 64-byte key, not just the string. Leftover stack bytes past the terminator meant even an exact, correctly-registered entry (including the compiled-in floor) silently never matched. Confirmed via `bpf_trace_printk`: the path printed correctly, but the direct map lookup still reported `found=0`. Fixed in `kb_lsm_file_open` by explicitly zero-filling `path_buf[len..63]` after `bpf_d_path()` returns. This means this specific block genuinely never enforced anything until this fix — not a regression, a pre-existing latent bug. [PardhuVarma]
- **`SetContainment` (used by `kb-tui`/`kbctl`) had never actually applied containment on the sensor side (`kb-control-plane/internal/ipc/types.go`)**: `MsgTypeContainmentCmd` was `3` in Go but the C side's `handle_incoming_containment_cmd()` checks for `KB_WIRE_MSG_CONTAINMENT_CMD` (`5`) — every containment command was silently dropped by the sensor. `kbd` logged a successful `SET_CONTAINMENT_*` audit entry regardless (the sensor never NACKs), masking the failure completely — `contained_pids_map` stayed empty no matter how many containment calls were made. Fixed by changing Go's constant to `5`. Confirmed via a live test: a test PID put into Seccomp containment via `kb-tui` had its sensitive-path access correctly blocked afterward, while an uncontained process reading the same file continued to succeed. [PardhuVarma]

### Removed
- **Blanket, unconditional `/etc/passwd` LSM file-block (`kb-core`)**: removed from the compiled-in floor entirely (see Changed above) — passive `KB_EV_PASSWD_ACCESS` scoring detection is kept.
- **Kafka Removal in AADS Subsystem (kb-aads/)**: removed kafka legacy code to implement low latency native uds communications fr inter-agent, and ray clusters.

---

## Incident: `sudo`/PAM lockout during live LSM-block verification (2026-07-17)

**What happened**: While verifying the zero-padding fix (see Fixed above), the LSM sensitive-path block fired correctly for the first time in this repo's history — and immediately blocked reads of `/etc/sudoers` and `/etc/shadow` system-wide, because the block was unconditional (applied to every process, not just contained ones) at the time this was tested. This broke `sudo` itself (`sudo: unable to open /etc/sudoers: Permission denied`) and PAM password authentication generally (`su`, `pkexec`, `login` — anything reading `/etc/shadow`) on the live test VM.

**Why recovery was hard**: Every standard privilege-escalation path needs one of the two now-blocked files: `sudo` reads `/etc/sudoers` on every invocation; PAM's `pam_unix` module reads `/etc/shadow` to verify a password, so even `pkexec` (a different authorization mechanism) failed at the PAM step. With no already-authenticated root shell or key-based root SSH login available, the only recovery path left was a full VM restart from outside the terminal (hypervisor/cloud console) — a reboot clears all BPF programs, including the stuck LSM hook, since they don't persist across boots.

**Root cause**: `kb_lsm_file_open`'s sensitive-path check was unconditional — it applied to every process on the system, not scoped to processes an operator had actually placed into containment. This was inconsistent with the containment-level model the code's own comments already documented (`kb-core/ebpf/kbd_sensor.bpf.c`'s "Containment level semantics" block says sensitive-path blocking belongs to level-2 containment) and inconsistent with every other LSM hook in the same file, all of which are already containment-gated.

**Resolution**: Made `kb_lsm_file_open` containment-gated, matching the rest of the file (see Changed above). Verified post-fix: `sudo whoami` succeeds cleanly with `kbd_sensor` actively running and enforcing; a deliberately-contained test process has its sensitive-path access blocked as intended, while every other process is unaffected.

**Takeaway for future work on this hook**: any change to `kb-core`'s LSM blocking logic should be tested by containing a *disposable* test process first, never verified by directly triggering system-wide "does the floor list block this path" checks against real `/etc/sudoers`/`/etc/shadow` on a machine you still need `sudo` on.

---

## Major Subsystem Milestones (Chronological History)

### July 2026

*   **2026-07-17** - `[d8c6665]` Add `kbtui.gif` and `kbtui.mp4` demonstrations of the new Rust-based TUI console (*PardhuVarma*)
*   **2026-07-17** - `[59b91a7]` Upgrade `test_all_hooks.sh` with realistic single-process sequential attack chains (Chain A, B, and C) to trigger SUSPICIOUS, BORDERLANDS, and COMPROMISED transitions for live alert stream verification (*Claude Code*)
*   **2026-07-17** - `[a387415]` `kb-tui` rebuilt as a real multi-panel ratatui/tonic operator console; `sensitive_paths` made operator-configurable end-to-end (`policy.yaml` → `kbd` → wire → sensor BPF map); found and fixed four live pre-existing bugs (connect-time hang, sensitive-paths frame collision, LSM zero-padding match failure, containment `msg_type` mismatch that meant `SetContainment` never actually worked); made LSM sensitive-path blocking containment-gated instead of blanket after a live `sudo`/PAM lockout incident during verification, requiring a VM reboot to recover (*Claude Code*)
*   **2026-07-16** - `[f4de926]` AADS gRPC-over-UDS client, UDS test suite, Ray remote actor base agents, JJE consensus, real connection verification script, and development plan (*Karthik*)
*   **2026-07-15** - `[7728598]` process exit lifecycle implementation, cache flushes, unit tests, and refactored SSH daemon-side architecture spec (*Tejaswini*); updated TUI README for Ratatui and kbd SSH delegation (*PardhuVarma*)
*   **2026-07-14** - `[faa87cb]` eBPF token bucket rate limiting, telemetry batching, and deep resource isolation (*PardhuVarma*)
*   **2026-07-14** - `[52b6a7a]` gap work implementation, LSM hook return corrections & IPC restore tests (*PardhuVarma*)
*   **2026-07-14** - `[3e3f790]` readme updates (*Rupa Karedla*)
*   **2026-07-13** - `[5d2a5a4]` git authorship documentation updates (*PardhuVarma*)
*   **2026-07-13** - `[55755dd]` Controlplane updates (*Tejaswini*)
*   **2026-07-13** - `[895a817]` CPM, CWP & Gap Fixation Updates (*PardhuVarma*)
*   **2026-07-11** - `[0379903]` `kb-control-plane`: wire IPC listener, enforcer construction, Contain() call sites (*Tejaswini*)
*   **2026-07-11** - `[72d89e7]` `kb-core`: containment restore and LSM enforcement coverage (*PardhuVarma*)
*   **2026-07-11** - `[77d1101]` `kb-core` sensor: autoload for TLS/SSL uprobes to resolve attachment failures (*PardhuVarma*)
*   **2026-07-11** - `[c4d5f04]` `kb-control-plane`: refined isProcessRunning argument matching to prevent false positives (*Tejaswini*)
*   **2026-07-11** - `[adfcc29]` `kb-control-plane`: normalized raw scoring values for HTTP/SSE feeds (*Tejaswini*)
*   **2026-07-11** - `[e87a070]` `kb-dashboard`: dynamic health indicators and performance metrics from daemon (*Rupa Karedla*)
*   **2026-07-11** - `[8538cbd]` `kb-dashboard`: Redesigned professional SOC console with sidebar, health panel, alert feed, and audit terminal (*Rupa Karedla*)
*   **2026-07-11** - `[8cc9ab7]` `kb-dashboard`: Initialized Vite-React-TypeScript dashboard with premium security telemetry visualization (*Rupa Karedla*)
*   **2026-07-09** - `[0852575]` `kb-checker`: removed Apache Kafka references in favor of ZeroMQ and Ray IPC (*Karthik*)
*   **2026-07-09** - `[090d733]` `kb-checker`: implement hard fallback containment locks in report recovery (*PardhuVarma*)
*   **2026-07-09** - `[49a2f51]` `kb-checker`: integrate systemd service controls in recovery (*PardhuVarma*)
*   **2026-07-09** - `[fadcc16]` `docs`: added Secure Boot-up Tampering Containment and Workload Gating Section (*PardhuVarma*)
*   **2026-07-08** - `[62ce504]` `kb-checker`: single-instance PID locking and signal cleanup (*PardhuVarma*)
*   **2026-07-08** - `[c399f12]` `kb-checker`: eBPF hook performance latency monitoring (*PardhuVarma*)
*   **2026-07-08** - `[898dbe9]` `kb-checker`: self-healing BPF map state integrity audits (*PardhuVarma*)
*   **2026-07-08** - `[cb022b8]` `kb-checker`: dynamic SHA-256 eBPF bytecode instructions hashing (*PardhuVarma*)
*   **2026-07-08** - `[ed27291]` `kb-checker`: modularized safety checker and status gRPC server over Unix Domain Sockets (*PardhuVarma*)
*   **2026-07-08** - `[72a79b8]` `kb-checker`: Rust safety daemon validation loops and gRPC/REST clients (*PardhuVarma*)
*   **2026-07-08** - `[a85f675]` `kb-core`: eBPF tasks for containment feedback loops and exit events (*PardhuVarma*)
*   **2026-07-07** - `[8c85a72]` `kb-op`: Integrated `kb-mcp` subsystem tool suite for operators (*PardhuVarma*)
*   **2026-07-07** - `[16395be]` `docs`: eBPF event rate limiting design specifications (*PardhuVarma*)
*   **2026-07-06** - `[02f0e3d]` `kb-core` & `kb-control-plane`: Integrated BPF LSM, behavior state machine, TLS uprobes, and fixed L2 DB race (*PardhuVarma & Tejaswini*)
*   **2026-07-04** - `[41df005]` `kb-control-plane`: SQLite3 database checks, core socket fallbacks, and major Go wiring updates (*Tejaswini & PardhuVarma*)
*   **2026-07-03** - `[0a691f9]` `kb-core`: eBPF scoring engine (`kb_scoring.c/.h`) and Unix socket streaming (`kb_bridge.c/.h`) (*PardhuVarma*)
*   **2026-07-01** - `[c11ec39]` `docs`: Rupa On-boarding and team info update (*Rupa Karedla & PardhuVarma*)
*   **2026-07-01** - `[0d539b9]` Userspace reorganization and build improvements (*PardhuVarma*)

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
