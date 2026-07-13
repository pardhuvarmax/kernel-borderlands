# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Kernel Borderlands (KB) is a kernel-level runtime defense framework for Linux: eBPF sensors observe kernel telemetry at Ring 0, a Go control plane scores and enforces, and a Python agent swarm coordinates adaptive response. Five subsystems, kept in sync via shared wire/event contracts — a change in one often requires a matching change in another (see Architecture).

See [README.md](README.md) for the project pitch and [docs/README.md](docs/README.md) for the full documentation index.

## Repository Layout

| Directory | Language | Role |
| --- | --- | --- |
| `kb-core/` | C (eBPF, CO-RE) | Ring-0 instrumentation (`kbd_sensor`) + userspace loader/bridge — see [kb-core/README.md](kb-core/README.md) |
| `kb-control-plane/` | Go | `kbd` daemon: ingestion, storage, scoring, gRPC, enforcement — see [kb-control-plane/README.md](kb-control-plane/README.md) |
| `kb-aads/` | Python | Agent Defense Swarm (MARL) — see [kb-aads/README.md](kb-aads/README.md) |
| `kb-checker/` | Rust | Stateless safety/integrity watchdog — see [kb-checker/README.md](kb-checker/README.md) |
| `kb-op/` | Go / Rust / TS | Operator interfaces (`kb-tui`, `kb-dashboard`, `kb-mcp`, `kbctl`) — see [kb-op/README.md](kb-op/README.md) |
| `docs/` | Markdown | Architecture specs, ADRs, event/wire contracts |
| `config/` | YAML | `kb.yaml`, `policy.yaml`, `allowlist.yaml`, `agents.yaml`, `dashboard.yaml` — see [config/README.md](config/README.md) |
| `scripts/` | Bash / Python | Setup, attack-lab simulation, dataset tooling — see [scripts/README.md](scripts/README.md) |
| `libbpf/` | C (vendored) | libbpf dependency for `kb-core` |

Full command reference (build/test/run for every subsystem) lives in [docs/development/developer-commands.md](docs/development/developer-commands.md) — prefer that over duplicating it here. Quick essentials:

```bash
cd kb-core && make && sudo ./build/kbd_sensor       # eBPF sensor (root required)
cd kb-control-plane && go test -v -count=1 ./...    # in-memory SQLite, no real state
cd kb-checker && cargo test
cd kb-aads && pytest
cd kb-op/kb-dashboard && npm run dev
```

## Architecture

Data flow: `kb-core` (Ring 0 eBPF) → UDS `/run/kb/kbd.sock` → `kb-control-plane` (`kbd`) → gRPC (:50051)/WebSockets → operator interfaces (`kb-tui`, `kb-dashboard`, `kbctl`, `kb-mcp`) and `kb-aads`. `kb-checker` runs independently, watchdogging the rest over its own UDS sockets.

Load-bearing references — read before touching cross-subsystem behavior:
- **Wire/event contract (kb-core ↔ kb-control-plane)**: [docs/architecture/kbd-contracts.md](docs/architecture/kbd-contracts.md), [docs/development/core-control/wire-protocol.md](docs/development/core-control/wire-protocol.md). Packed LE structs (`ProcessState`=128B, `ZoneTransition`=40B, `kb_wire_attack_rule`=220B) and locked `event_type` values — C and Go sides must change together.
- **Kernel hook points**: [docs/architecture/hookpoints.md](docs/architecture/hookpoints.md).
- **Socket topology & boot order**: [docs/architecture/boot_sequence_spec.md](docs/architecture/boot_sequence_spec.md), [docs/development/core-control/kba_uds_binding_spec.md](docs/development/core-control/kba_uds_binding_spec.md). Sockets under `/run/kb/`: `kbd.sock` (telemetry), `kba.sock` (gRPC enforcement IPC), `kbc.sock` (kb-checker diagnostics).
- **Storage design (L1 sync.Map / L2 SQLite WAL)**: [docs/development/adr/ADR-1.md](docs/development/adr/ADR-1.md); other ADRs in [docs/development/adr/](docs/development/adr/).
- **BPF LSM setup**: [docs/architecture/enabling-bpf-lsm.md](docs/architecture/enabling-bpf-lsm.md). **Cross-kernel portability (BTF/CO-RE)**: [docs/architecture/cross-kernel-portability.md](docs/architecture/cross-kernel-portability.md).
- **kb-checker's KISS/no-state/no-network constraints**: [kb-checker/README.md](kb-checker/README.md) — this is a security-critical design invariant, not a style preference; don't add persistent state or network listeners to it.
- **Feature specs** (behavior engine, dynamic rules, CPM/CWP, TLS plaintext monitoring, in-context mitigation, Ray integration): [docs/features/](docs/features/).
- **Full system spec**: [docs/specifications/kernel_borderlands_specification.md](docs/specifications/kernel_borderlands_specification.md).

## Conventions

- **Shared structs stay byte-identical**: edits to wire structs must keep the C (`__attribute__((packed))`) and Go layouts in sync — verify against [docs/architecture/kbd-contracts.md](docs/architecture/kbd-contracts.md).
- **Rules/policy are compiled, not hand-edited on the sensor side**: `config/policy.yaml` / `rules.yaml` are compiled by `kb-control-plane` and pushed to the C sensor over the bridge at connect time.
- **Commit authorship**: shared working copy, multiple contributors — never change repo `user.name`/`user.email`; use `git commit --author="Name <email>" -m "..."` per [docs/development/git-authorship.md](docs/development/git-authorship.md).
