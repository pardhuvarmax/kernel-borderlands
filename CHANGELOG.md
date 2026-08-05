# Changelog

All notable changes to the **Kernel Borderlands** project are documented below.

---

## [Unreleased] - 2026-08-05

### Added
- **Out-of-Band Attestation Node proposal, v0.2 (`docs/features/oan-hardware-appliance.md`, renamed/superseding `docs/features/kbc-hardware-watchdog.md`)**: Documentation-only proposal (not implemented) for a physically independent hardware appliance — SBC (attestation/policy engine) + STM32 (deterministic safety controller/watchdog, survives an SBC-side Linux crash) + ESP32 (management/comms only, no security decisions) + TPM 2.0 root of trust + relay-based host fencing — that attests and can fence a Kernel Borderlands host from outside its trust boundary, covering the one failure mode software-only same-host watchdogging can't structurally address: full kernel compromise. Reframed from v0.1's "`kb-checker` hardware extension" framing to a standalone future subsystem (working name `kb-hw/`, not yet created) that continues `kb-checker`'s external-verification role rather than being part of it. Updated bill of materials for the 3-processor design (~$105–$215 bench prototype); added a production-appliance concept (enclosure, front-panel LEDs, display) and cluster-supervision direction, both explicitly out of prototype scope; rejected inline-hardware (FPGA/DPU) tier carried over unchanged. Open questions expanded (repo placement/naming, internal SBC↔STM32↔ESP32 protocol, research-contribution claims needing a literature comparison) on top of v0.1's unresolved wire protocol, failure semantics, and TPM integration point. [PardhuVarma]
- **Fabric Management Service proposal (`docs/features/oan-fms.md`)**: Documentation-only proposal (not implemented) for OAN's fleet-orchestration sub-service, expanding `oan-hardware-appliance.md` §9 from a two-line "future work" stub into a full design direction — Fabric → Colony → Family → Node hierarchy, discovery/registry/membership, policy inheritance across hierarchy levels, health monitoring, event aggregation, cross-host correlation, recovery coordination, and deployment management. Explicitly scoped to come after a working single-host OAN prototype, not before. Flags two unresolved risks rather than asserting the design is sound: whether centralizing fleet management on one OAN reintroduces the single-point-of-failure problem OAN exists to avoid per host, and an apparent conflict between FMS's multi-node reporting channel and OAN's "never the host's primary network" principle from the parent doc. [PardhuVarma]
- **OAN/FMS design resolution: Two Communication Planes + Local Autonomy Principle (`docs/features/oan-hardware-appliance.md`, `docs/features/oan-fms.md`)**: Closed both risks flagged in the FMS proposal above, same day. OAN now exposes two independent, never-shared interfaces (`oan-hardware-appliance.md` §3.1): an **OOB Trust Plane** (SBC's existing serial/dedicated-Ethernet link to the host's `kb-checker` — attestation, heartbeat, recovery) and a **Fabric Management Plane** (ordinary but hardened networking — dedicated VLAN/NIC/isolated switch — carried on the ESP32, §4.3, used only by FMS/dashboards/policy sync). FMS itself is reclassified under a **Local Autonomy Principle** (`oan-fms.md` §3.1): every node keeps full local protection with zero dependency on FMS, so FMS is operationally important but explicitly not security-critical. Fleet reporting is data-minimized to signed summaries (health/alerts/inventory/version/integrity status) rather than raw telemetry or BPF map access (`oan-fms.md` §11.1) — signing-key provenance for those summaries is a new open question, tied to the parent doc's still-unresolved TPM integration point. Multi-OAN scale direction also decided: no global master, each Colony keeps its own autonomous OAN/FMS pair; the actual cross-OAN sync protocol remains undesigned. [PardhuVarma]
- **OAN §9 rewritten: dedicated-per-host vs. shared-chassis deployment models, capped and costed (`docs/features/oan-hardware-appliance.md`)**: Answers "does every protected machine need its own OAN?" with two named models instead of the earlier single ambiguous cluster diagram — **Model A** (one full OAN unit per host, simplest, no shared failure domain) and **Model B** (one shared chassis serving up to 5 co-located hosts, hard-capped for blast-radius/commodity-part reasons, §9.2). Model B's OOB transport corrected mid-design from a naive point-to-point-serial fan-out (doesn't scale) to a dedicated, physically isolated Ethernet segment per chassis — explicitly not a VLAN on the host's own NIC, since that would still be driven by a potentially-compromised host kernel; modeled on the same pattern enterprise BMC/IPMI management networks and managed PDUs already use. Added §4.2.1 explaining why fencing/heartbeat logic sits on a dedicated STM32 rather than the SBC (avoids re-coupling the watchdog to Linux's own failure domain) or the ESP32 (kept out of the trust-critical path due to its larger, network-facing attack surface) — "SBC = brain, ESP32 = mouth, STM32 = spinal reflex." Added full USD/INR cost tables: shared-vs-per-host component split, single/triple/pentagon(5)/30-host worked examples, itemized per-host cost breakdown (STM32/relay/OOB dongle/wiring), and the marginal cost of filling one chassis to its 5-host cap (~$128–$188 / ₹11,140–₹16,360 for hosts 2–5, on top of one $74–$148 fixed chassis cost). New open questions 9–10 flag that the OOB dongle line item is still an approximation and that neither model has an actual built/tested reference design yet. [PardhuVarma]
- **Cost-reduced OAN BOM appendix (`docs/features/hardware-ext/oan-cheap.md`, alt.)**: Documentation-only companion to `oan-hardware-appliance.md`'s Model B shared-chassis BOM — tags each cost-reduction option (Pi Zero 2 W, bare ESP32/STM32 modules instead of dev-kit boards, shared multi-channel relay board, dropped optional display, generic OOB dongle) as either "free" (no change to OAN's threat model) or "trade-off" (discrete TPM → firmware TPM is the one flagged, and explicitly not recommended by default, since it removes the design's hardware-rooted trust guarantee). Brings a Pentagon (5-host) chassis from $234–$383/₹20,360–₹33,320 down to $114–$168/₹9,918–₹14,616 (~$11–$17 per person on a 10-person team) without the TPM trade-off. Notes bulk/wholesale sourcing doesn't apply at 5-unit scale — the savings come from cheaper parts, not order volume. Does not change architecture or `oan-hardware-appliance.md`'s open questions. [PardhuVarma]
- **fTPM cost-cut rejected in `oan-cheap.md` §3.7, same day**: Investigated whether swapping the discrete TPM for a firmware TPM (fTPM) was a viable savings, since it looked like the single biggest line item ($20–$40 → $0). Rejected: fTPM is a SoC feature, not a purchasable part — Intel chips have it built in (Intel PTT, free BIOS toggle) but Raspberry Pi does not, and getting one there would need an unproven OP-TEE + TPM2 Trusted-Application port reworking Pi's non-standard boot chain, with uncertain maturity on Pi 5's SoC specifically. Even if built, it would only deliver TrustZone-level logical isolation on the same chip as the SBC, not a discrete chip's physical separation — and the saving involved (~$4–$8/host amortized) doesn't justify either the engineering risk or the weakened guarantee, especially given the self-undermining angle: OAN exists specifically because software-rooted trust isn't considered sufficient, so rooting OAN's own trust in firmware reintroduces that same weakness at OAN's foundation. Verdict: discrete TPM stays in both the reference and cost-reduced BOMs; `oan-cheap.md` §7's open question on this is now resolved. [PardhuVarma]
- **Containment RL training pipeline (`scripts/dataset/`, `kb-aads/marl/`)**: Built a real dataset pipeline (`collect.py`/`label.py`/`split.py`) using [ADFA-LD](https://www.unsw.adfa.edu.au/unsw-canberra-cyber/cybersecurity/ADFA-IDS-Datasets/) real Linux syscall-sequence traces — a host-based IDS dataset matching kb-core's actual observation surface, chosen after correctly rejecting an initial NSL-KDD (network-flow) attempt as a mismatch for what KB hunts. Maps 5 of KB's 6 attack-lab scenarios onto ADFA-LD categories (`memory_exploit.sh` has no equivalent — stated, uncovered gap), plus real `/proc` telemetry sampled from the dev machine for benign-class diversity. Full report: [`docs/reports/kb-aads/containment-rl-2026-08-02.md`](docs/reports/kb-aads/containment-rl-2026-08-02.md). [Karthik] [PardhuVarma]
- **Fixed `ContainmentEnv` (`kb-aads/marl/env.py`)**: Replaced the `AADSEnv` stub (single-step, placeholder observations, hardcoded reward) with a real Gymnasium env — observation is the actual `ProcessState`/`KBEvent` wire-field shape, reward computed from labeled targets with an over-/under-containment asymmetry. [Karthik] [PardhuVarma]
- **RLlib PPO training via `colab` CLI (`kb-aads/marl/train_containment.py`, `COLAB_CLI_TRAINING.md`, `remote_train_driver.py`)**: Trained Containment's policy remotely on a Colab CPU session (no local GPU on the dev machine). Final held-out test-set result: 84.4% overall accuracy, 97-100% on every real attack category, **0% under-containment rate**. Full training transcript at `kb-aads/marl/session.log`. [Karthik] [PardhuVarma]
- **Live inference wiring (`kb-aads/agents/containment.py`)**: `ContainmentAgent` now loads the trained checkpoint via `RLModule.from_checkpoint` (inference-only) and drives real containment decisions instead of doing nothing — falls back to `NONE` + explicit `model_loaded: False` if no checkpoint exists, never guesses. [Karthik] [PardhuVarma]
- **Live pipeline demo (`kb-aads/demo/live_containment_monitor.py`)**: Long-running driver that streams real `KBEvent`s from a live `kb-control-plane`, fetches each PID's real `ProcessState`, and feeds it to a persistent, trained `ContainmentAgent` actor — verified against the actual running `kb-core` sensor + `kb-control-plane` on this machine, not synthetic data. [Karthik] [PardhuVarma]
- **base ppr draft (ongoing work)** (`latex/paper/`): arXiv-style LaTeX draft covering all five subsystems (architecture, implementation history, defects, current status), with the Containment RL work as one subsection rather than the whole paper. Built on the `kourgeorge/arxiv-style` template. [PardhuVarma]

### Changed
- **`kb-aads/marl/checkpoints/containment_ppo/` un-ignored and committed (`.gitignore`, `kb-aads/marl/checkpoints/`)**: Initially gitignored as a regenerable binary build artifact (same treatment as `kb-core/build/`, Rust `target/`, etc.). Reversed — each checkpoint is confined to its own subdirectory and this one is only ~1.8MB, so committing it keeps the repo immediately runnable (clone and go) without requiring a retrain first. Re-evaluate if a future checkpoint (Jury/Healer, or a larger model) is significantly bigger. [Karthik]

### Fixed
- **`event_type` feature collision in Containment's training data (`scripts/dataset/label.py`)**: First training run scored only 60-73% on `CGROUP`/`SECCOMP` specifically because `credential_access`/`lateral_movement` shared the same engineered `event_type` code and `zone` floor, leaving the trained policy almost nothing to distinguish them by. Gave each of the 6 categories a distinct `event_type` code and retrained; those two levels went to 100% in the retrain, at the cost of `NONE` dropping 100%→82.2% (an accepted trade — over-caution on benign traffic beats a missed threat for a containment system). [Karthik] [PardhuVarma]
- **`.gitignore`'s dataset-raw rule never matched anything**: `kernel-borderlands/scripts/dataset/output/raw` had a stray path prefix relative to where `.gitignore` actually lives, so `scripts/dataset/output/raw/` (real downloaded datasets, real local telemetry samples) was never actually ignored. Fixed to `scripts/dataset/output/raw/`; also added `scripts/zips/` (binary/regenerable training bundles — `kb-aads/marl/checkpoints/*` was added here too but see Changed above, since reversed). [Karthik] [PardhuVarma]
- **Upstream `google-colab-cli` `colab install` crash**: `jupyter_kernel_client` 1.0.0 removed/renamed the `KernelClient` class the CLI's bundled version depends on. Pinned `jupyter_kernel_client==0.15.0` in the tool's isolated `uv` venv to restore the expected API — not a change to this repo's own code, but blocking anyone else using the same `colab` CLI setup for training. [Karthik] [PardhuVarma]

---

## [8335f23] - 2026-08-02

### Added
- **CPM eBPF-side registration + CWP (Critical Workload Protection) scaffolding (`kb-core`)**: `protected_pids_map`/`protected_exec_paths_map` exec/exit-time registration hooks per `docs/features/CPM.md`, plus a new `protected_workloads_map` (8192 entries, path- or hash-identity tier) implementing `docs/features/CWP.md` §5-6.1 — evaluated strictly after CPM, never merged with it. SHA-256 hashing (`kb_sha256.c`/`.h`) added for hash-based workload identity. `kb-core/tests/test_cwp.py` added; owner-team/justification alerting (§9) explicitly out of scope for this pass. [PardhuVarma]
- **Knowledge graph published (`docs/index.html`, `graphify-out/`)**: A `graphify`-generated knowledge graph of the whole codebase (1,924 nodes, 3,146 edges, 178 communities — vendored `vmlinux.h` BTF excluded so the graph reflects KB's own architecture, not kernel-header noise), linked from the site's new `#graph` section and footer. [PardhuVarma]

---

## [2b35dc9] - 2026-07-30

### Added
- **`kbctl` CLI (`kb-op/kbctl/`)**: New standalone Go CLI (`cmd_audit.go`, `cmd_policy.go`, `cmd_process.go`, `cmd_stats.go`, `cmd_zone.go`) talking to `kb-control-plane` over its gRPC API, plus new `kb.proto` RPCs/messages backing it and `internal/controlplane/grpc.go`/`http.go` handlers to serve them. [Tejaswini4119]
- **Audit chain support (`kb-control-plane/internal/store`, `internal/controlplane`)**: New store-layer methods and gRPC plumbing for querying the audit trail `kbctl audit` reads. [Tejaswini4119]
- **`docs/emergency-backup/` — standalone per-subsystem documentation (`kb-aads.md`, `kb-core.md`, `kb-cp.md`, `kb-op.md`, plus a `README.md` index)**: ~5,300 lines added across several commits, written so each subsystem could be forked and continued independently "in case the team disbands". [PardhuVarma]

---

## [f8096ac] - 2026-07-28

### Added
- **CPM (Containment Policy Manager) authorization gate (`kb-core`)**: `cpm_classify()` in `handle_incoming_containment_cmd()` now rejects containment of PID 1, kernel threads, self-registered sensor components, and a protected-executable registry, per `docs/features/CPM.md`. Classifier lives in userspace C (not in-kernel eBPF) since that's where the actual containment-map write happens — a documented deviation from the spec's literal diagram. Verified live against the real sensor (`kb-core/tests/test_cpm.py`). [PardhuVarma]
- **`kbd.sock`/`kbct.sock` socket split (`kb-core`, `kb-control-plane`)**: Telemetry and containment commands were previously multiplexed on one raw socket connection — a telemetry-volume burst could fill the send buffer, and `write()` returning `EAGAIN` was misread as a dead connection, taking containment delivery down as collateral damage. Split control traffic (containment cmds, sensitive-path/rules pushes) onto a new `kbct.sock`, leaving `kbd.sock` telemetry-only; `kb-control-plane`'s `NewListener()`/`New()` now bind both. Also ignores `SIGPIPE` process-wide. Verified live: a containment command for a protected PID was delivered and rejected correctly while the connection was simultaneously saturated with unrelated telemetry. [PardhuVarma] [Tejaswini4119]
- **`kb-aads` `ControlPlaneClient` streaming/unary mixing guard (`kb-aads/comms/grpc_client.py`)**: Same class of coupling the socket split fixed, at the gRPC-channel layer — a stalled `stream_events`/`stream_alerts` consumer sharing a channel with a latency-sensitive unary call (`submit_decision`, etc.) could delay the unary response. Not live yet (no caller used the streaming methods at the time), fixed pre-emptively. 3 new tests, all passing. [Karthik]

### Fixed
- **Containment-cmd read path reset the wrong bridge fd (`kb-core`)**: The error handler unconditionally reset the global `bridge_fd` instead of whichever fd was actually passed in — found while wiring up the socket split. [PardhuVarma]
- **`test_cpm.py`/`test_restore_ipc.py` silently no-op after the socket split (`kb-core/tests`)**: Both mock-control-plane test drivers bound only `kbd.sock` and sent containment commands there; post-split, `kbd_sensor` no longer reads containment commands from that connection, so these scripts reported success while doing nothing. Updated both to use `kbct.sock`. [PardhuVarma]
- **Stale `kbd.sock`-carries-everything documentation, corrected across the board**: `CPM.md`, `cpm-implementation.md`, `boot_sequence_spec.md`, `wire-protocol.md`, `ipc-v3-wiring.md`, `developer-commands.md`, `worksheet.md`, `specifications/README.md` (which also incorrectly called `kbd.sock` gRPC — `kba.sock` is), `kb-control-plane/README.md`, `cmd/README.md`, and `CLAUDE.md` all still described `kbd.sock` as carrying containment commands or being kb-core's only socket. [PardhuVarma] [Tejaswini4119]
- **`comms/README.md`/`demo/README.md` described ZeroMQ as current**: No `import zmq` exists anywhere in `kb-aads` — ZeroMQ was dropped for Ray before these docs were last touched. New `docs/development/control-aads/kb-events-swarm-ingestion-gap.md` documents, with code citations, that nothing currently consumes `StreamEvents`/`StreamAlerts` at all. Also corrected `aads-intelligence-roadmap.md`'s claim that CPM/CWP is a "scoring engine" (`CPM.md` is explicit it isn't). [Karthik]

---

## [452b64d] - 2026-07-26

### Added
- **Academic/major-project submission materials (`docs/project/major-project-submissions/`)**: PPTX, synopsis PDF, and README/video-link updates for the university major-project review cycle — non-engineering, not detailed individually here. [PardhuVarma]

---

## [8b6a3a2] - 2026-07-24

### Added
- **`kb-aads` actor scaffolding fixed from non-functional to a verified-working skeleton (`kb-aads/agents/`)**: `BaseAgent` was previously decorated `@ray.remote` directly, which throws `ActorClassInheritanceException` the moment any subclass (`HunterAgent`, `PatrollerAgent`, ...) tries to also apply `@ray.remote` — no concrete role actor could actually be constructed. Removed the decorator from `BaseAgent` itself; added `RemoteBaseAgent = ray.remote(BaseAgent)` for roles with no dedicated subclass. Added `AgentState.last_action` and surfaced it via `get_status()`. Added `ExecutorAgent` (`kb-aads/agents/executor.py`) — the first real gateway back to `kb-control-plane`, submitting consensus decisions over `kba.sock` via `submit_decision`. Added `config/agents.yaml` (swarm composition). [Karthik]
- **AADS Intelligence Roadmap (`docs/development/control-aads/aads-intelligence-roadmap.md`)**: Initial roadmap from skeleton agents to trained agents — the per-agent RL/LLM/no-model assignment table, JJE's courthouse-for-sub-agents design, and the phased Phase 0-6 plan this session's Containment training work (see `[Unreleased]` above) partially executes against. [Karthik]
- **Resource management roadmap (`docs/architecture/resource_management_roadmap.md`, `kb-core_system_requirements.md`)**: New architecture docs covering planned resource-management/fleet-deployment direction. [PardhuVarma]
- **Product plan, years 1-2 (`docs/project/kbgoal2yrs.md`)**: Longer-term product roadmap document. [PardhuVarma]

### Fixed
- **Stale cross-references across `docs/`**: Corrected references in `docs/README.md`, `docs/features/README.md`, `docs/reports/README.md`, `docs/specifications/README.md`, `docs/development/core-control/README.md`, and media READMEs after the AADS roadmap and other docs churn left several pointing at moved/renamed files. [Karthik]

---

## [a525f41] - 2026-07-23

### Added
- **`kb-checker` gRPC health-verification channel (`kb-control-plane/internal/checkerclient/`, `proto/checker/`)**: New `checkerclient.go` client plus `checker.proto`/generated Go stubs, letting `kb-control-plane` query `kb-checker`'s health over gRPC — the Go-side half of the `kbd`↔`kb-checker` diagnostic channel referenced in `control-plane-catalog.md`. [Tejaswini4119]
- **Resource management / kb-core system requirements docs (`docs/architecture/`)**: Further build-out of `resource_management_roadmap.md` and `kb-core_system_requirements.md`. [Tejaswini4119] [PardhuVarma]
- **`control-plane-catalog.md` expanded (`docs/development/core-control/`)**: Substantial documentation additions describing the control-plane socket/service catalog — despite several of this date's commit messages referencing "http.go :80xx tcp port" changes, the actual diffs are documentation-only; no `http.go` TCP-port code change landed under these commits. [Tejaswini4119]

---

## [8a3286a] - 2026-07-18

### Added
- **Demo-run telemetry media (`media/demoruns/`)**: READMEs and a tracked demo-run telemetry video, plus general README polish. [PardhuVarma]

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
