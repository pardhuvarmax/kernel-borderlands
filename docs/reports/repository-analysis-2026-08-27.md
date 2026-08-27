# Kernel Borderlands Repository Analysis Report (2026-08-27)

## 1) Scope

This report analyzes the current repository state across:
- `kb-core` (C/eBPF sensor)
- `kb-control-plane` (Go daemon)
- `kb-aads` (Python agentic swarm)
- `kb-checker` (Rust watchdog)
- `kb-op` (`kb-tui`, `kb-dashboard`, `kb-mcp`, `kbctl`)
- docs/config/scripts and CI workflow posture

Focus areas requested:
1. Testing posture
2. Coverage posture
3. Agentic-module security
4. Test-case inventory
5. Bug report with actionable findings

---

## 2) Repository-Level Architecture Snapshot

The platform is split into five runtime subsystems with documented contracts in:
- `docs/specifications/kernel_borderlands_specification.md`
- `docs/architecture/kbd-contracts.md`
- `docs/development/core-control/wire-protocol.md`

High-level flow:
- `kb-core` emits telemetry over `/run/kb/kbd.sock`
- `kb-control-plane` ingests, scores, stores (L1 `sync.Map`, L2 SQLite)
- control actions flow back via `/run/kb/kbct.sock`
- `kb-aads` and operator surfaces communicate over `/run/kb/kba.sock` (gRPC over UDS)
- `kb-checker` watchdogs integrity and service health

---

## 3) Testing Status (Current State)

## 3.1 Test assets discovered

- `kb-core/tests`: 11 files (includes scripts, logs, utilities, C/Python tests)
- `kb-control-plane`: 9 Go `_test.go` files
- `kb-checker/tests`: 2 files (`README.md`, `checker_tests.rs`)
- `kb-aads/tests`: 3 files (`README.md`, `test_grpc_client.py`, `verify_real_connection.py`)
- `kb-op`: no dedicated automated test files detected

## 3.2 Commands executed in this analysis

### Successful
1. `kb-control-plane`: `go test -count=1 ./...` ✅
2. `kb-control-plane` coverage run on tested internal packages ✅
3. `kb-op/kbctl`: `go test ./...` ✅ (`[no test files]`)
4. `kb-op/kb-mcp`: `go test ./...` ✅ (`[no test files]`)

### Failed / blocked
1. `kb-aads`: `pytest -q` ❌ (`pytest: command not found` in environment)
2. `kb-checker`: `cargo test` ❌ (missing `libelf` headers / pkg-config discovery)
3. `kb-op/kb-tui`: `cargo test` ❌ (`protoc` not installed)

## 3.3 CI workflow posture

Only one workflow file is present:
- `.github/workflows/retry-pages-deploy.yml`

Observation:
- Current GitHub Actions config does **not** run subsystem tests/lint/build by default.
- Existing workflow only retries failed Pages deployment jobs.

---

## 4) Coverage Status

## 4.1 Measured coverage (from executed run)

`kb-control-plane` package-level coverage:
- `internal/controlplane`: 22.3%
- `internal/enforcement`: 100.0%
- `internal/ipc`: 51.8%
- `internal/policy`: 98.0%
- `internal/ssh`: 15.6%
- `internal/store`: 45.7%
- **Total (tested internal packages): 34.6% statements**

## 4.2 Coverage posture by subsystem

- `kb-control-plane`: measurable; partial and uneven.
- `kb-core`: test scripts exist, but no centralized coverage artifact generation observed.
- `kb-aads`: unit/integration tests exist, but no active coverage report generation configured in repo.
- `kb-checker`: tests exist but currently blocked by environment dependencies in this run.
- `kb-op`: largely lacks automated test suites (especially dashboard and MCP/CLI logic).

## 4.3 Coverage gaps (high impact)

1. No repository-wide unified coverage pipeline.
2. Agentic path (`kb-aads`) has narrow test surface relative to role complexity.
3. Operator modules are minimally or not test-instrumented.
4. CI does not enforce minimum coverage thresholds.

---

## 5) Agentic Module Security Analysis (`kb-aads`)

## 5.1 Positive security controls observed

1. UDS-based local control-plane transport (`/run/kb/kba.sock`) in `comms/grpc_client.py`.
2. Explicit channel-role separation guard in `ControlPlaneClient` (prevents unary/stream multiplexing misuse on same instance).
3. Clear acknowledgment in docs of ingestion gap and stale ZeroMQ assumptions fixed in `kb-aads/comms/README.md`.
4. Structured decision submission path via `ExecutorAgent` back to control-plane (`SubmitAgentDecision`) rather than direct enforcement in agent code.

## 5.2 Security risks / design concerns

1. **Ray dashboard exposure in local mode**
   - File: `kb-aads/swarm/orchestrator.py`
   - `ray.init(..., dashboard_host="0.0.0.0")` exposes dashboard on all interfaces.
   - Risk: unnecessary visibility surface in environments where host network boundary is weak.

2. **Insecure gRPC channel semantics**
   - File: `kb-aads/comms/grpc_client.py`
   - Uses `grpc.insecure_channel(...)`; transport is UDS, which is local and acceptable for many deployments, but authz relies on filesystem/socket permissions only.
   - Risk: privilege boundary is host-local only; no peer identity verification.

3. **Swarm event-ingestion not live**
   - File: `kb-aads/comms/README.md`
   - Documented known gap: no active path consuming `stream_events`/`stream_alerts` in live agents.
   - Risk: reduced real-time detection efficacy despite available RPC interfaces.

4. **Role logic still partially stubbed**
   - File: `kb-aads/agents/hunter.py`
   - TODO-marked investigation flow for evidence chain and confidence calculations.
   - Risk: incomplete investigation logic can cause inconsistent decision quality.

---

## 6) Test Case Inventory (Current + Needed)

## 6.1 Current, implemented tests

### `kb-control-plane`
- RPC behavior tests (`GetProcessState`, `OverrideZone`, `ReloadPolicy`, audit chain/export)
- IPC wire-layout and parser tests (exact byte-size checks: 128B `ProcessState`, 40B `ZoneTransition`)
- Policy, enforcement, store, SSH key/auth parsing tests

### `kb-core`
- `test_behavior.c`: state transitions, IOC sequence, time-window validation
- `test_all_hooks.sh`: live integration trigger script for hook/event coverage
- Python integration-style scripts for CPM/CWP/IPC restore pathways

### `kb-aads`
- `test_grpc_client.py`: mock gRPC server tests for unary and stream methods + guard behavior
- `verify_real_connection.py`: real UDS communication verification utility

### `kb-checker`
- `checker_tests.rs`: mock UDS gRPC health-server integration check

## 6.2 Recommended additional test cases

1. `kb-aads` end-to-end event ingestion tests (StreamEvents -> Hunter/Patroller -> Judge/Jury -> Executor).
2. `kb-aads` role-behavior tests for Hunter/Healer/Jury edge cases and malformed payload handling.
3. `kb-op/kb-dashboard` frontend tests (component + state + WebSocket mock).
4. `kb-op/kb-mcp` tool contract tests (request/response schema and failure behavior).
5. `kb-checker` negative-path tests for retry/failure logic in swarm health and recovery branches.
6. CI-level integration smoke tests for socket topology (`kbd.sock`, `kbct.sock`, `kba.sock`, `kbc.sock`).

---

## 7) Bug Report / Findings

## BR-001: No automated CI test workflow (High)
- Evidence: only `.github/workflows/retry-pages-deploy.yml` present.
- Impact: regressions can merge without automated validation.
- Recommendation: add multi-job CI for Go/Python/Rust/frontend test and build checks.

## BR-002: `kb-aads` tests are blocked in clean environment (Medium)
- Evidence: `pytest` missing; no automated setup path executed in CI.
- Impact: agentic test reliability depends on manual environment preparation.
- Recommendation: add reproducible test bootstrap (venv + pinned deps + CI job).

## BR-003: `kb-checker` tests fail due native dependency prerequisites (Medium)
- Evidence: `cargo test` failed requiring `libelf` headers/pkg-config linkage.
- Impact: watchdog validation cannot run out-of-box in minimal environments.
- Recommendation: document/install prerequisites in automated setup or containerized test runner.

## BR-004: `kb-tui` tests fail without `protoc` toolchain (Medium)
- Evidence: `cargo test` error: `Could not find protoc`.
- Impact: operator TUI cannot be validated in default runner images.
- Recommendation: include protobuf compiler in developer/CI bootstrap.

## BR-005: Agentic ingestion path is explicitly not wired (High)
- Evidence: `kb-aads/comms/README.md` “Known gap: no live path for kb-events reaching the swarm”.
- Impact: swarm cannot consume live telemetry despite having streaming client methods.
- Recommendation: implement and test live stream consumer path and message-shape adapters.

## BR-006: Ray dashboard bound to `0.0.0.0` in local mode (Medium)
- Evidence: `kb-aads/swarm/orchestrator.py` local `ray.init(...dashboard_host="0.0.0.0")`.
- Impact: expands network-visible attack surface unnecessarily.
- Recommendation: default to loopback binding unless explicitly overridden by secure config.

---

## 8) Priority Actions

1. Add CI test/build workflows for all subsystems.
2. Close `kb-aads` live-ingestion gap and add end-to-end swarm decision tests.
3. Standardize dependency bootstrap (Python, Rust native deps, protobuf compiler).
4. Increase `kb-control-plane` coverage in low-coverage packages (`internal/ssh`, `internal/controlplane`, `internal/store`).
5. Harden default agentic runtime network exposure (Ray dashboard binding).

---

## 9) Evidence Sources Consulted

Key docs and code used in this analysis:
- `README.md`
- `docs/README.md`
- `docs/development/developer-commands.md`
- `docs/specifications/kernel_borderlands_specification.md`
- `docs/specifications/safety_integrity_design_spec.md`
- `docs/specifications/operator_interfaces_spec.md`
- `kb-aads/README.md`
- `kb-aads/comms/README.md`
- `kb-aads/comms/grpc_client.py`
- `kb-aads/swarm/orchestrator.py`
- `kb-aads/agents/*.py`
- `kb-aads/tests/*`
- `kb-control-plane/internal/**/*_test.go`
- `kb-core/tests/*`
- `kb-checker/tests/checker_tests.rs`
- `.github/workflows/retry-pages-deploy.yml`

