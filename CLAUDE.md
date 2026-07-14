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
| `libbpf/` | C (vendored) | libbpf dependency for `kb-core` |The handoff should allow another coding session or a human developer to continue the work with or eithout any further minimal additional investigations.


## Documentation Policy

- The documentation under `docs/` is the canonical source of truth for this repository.
- Before implementing features, modifying code, refactoring, debugging, or making architectural decisions, consult the relevant documentation first.
- When documentation and implementation disagree, do not assume the code is correct. Explain the discrepancy and ask for clarification before changing behavior.
- When proposing or implementing non-trivial changes, mention the documentation files consulted whenever they materially influenced the implementation.
- Consult only the documentation relevant to the current task. Do not read unrelated documentation unless required.

## Primary Documentation

1. Specifications : 
    [docs/specifications/](docs/specifications/)

2. Architecture :
    [docs/architecture/](docs/architecture/)

3. Development :
    [docs/development/](docs/development/)

4. Features (Evolving) :
    [docs/features/](docs/features/)

## Workflow

For every non-trivial task:

1. Identify the relevant documentation. Read only the files necessary for the current task.
2. Verify expected behavior and interfaces in `docs/specifications/`.
3. Confirm architectural consistency using `docs/architecture/`.
4. Implement the requested changes.
5. If the implementation conflicts with the documentation, do not guess or silently change behavior—explain the conflict and ask for clarification.
6. If required documentation does not exist, state that explicitly instead of inferring undocumented architecture.
7. Prefer the smallest correct change that satisfies the request. Avoid unrelated refactors.

Documentation precedence:

1. `docs/specifications/`
2. `docs/architecture/`
3. `docs/development/`
4. `docs/features/`
5. Source code
6. General knowledge

Treat these directories as the project's canonical knowledge base. Prefer documented behavior over assumptions, and preserve documented contracts unless explicitly instructed otherwise.

Full command reference (build/test/run for every subsystem) lives in [docs/development/developer-commands.md](docs/development/developer-commands.md) — prefer that over duplicating it here. Quick essentials:

```bash
cd kb-core && make && sudo ./build/kbd_sensor       # eBPF sensor (root required)
cd kb-control-plane && go test -v -count=1 ./...    # in-memory SQLite, no real state
cd kb-checker && cargo test
cd kb-aads && pytest
cd kb-op/kb-dashboard && npm run dev
```

## Architecture

Data flow: `kb-core` (Ring 0 eBPF) → UDS `/run/kb/kbd.sock` → `kb-control-plane` (`kbd`) → gRPC (UDS)/WebSockets → operator interfaces (`kb-tui`, `kb-dashboard`, `kbctl`, `kb-mcp`) and `kb-aads`. `kb-checker` runs independently, watchdogging the rest over its own UDS sockets.

Load-bearing references — read before touching cross-subsystem behavior:
- **Wire/event contract (kb-core ↔ kb-control-plane)**: [docs/architecture/kbd-contracts.md](docs/architecture/kbd-contracts.md), [docs/development/core-control/wire-protocol.md](docs/development/core-control/wire-protocol.md). Packed LE structs (`ProcessState`=128B, `ZoneTransition`=40B, `kb_wire_attack_rule`=220B) and locked `event_type` values — C and Go sides must change together.
- **Kernel hook points**: [docs/architecture/hookpoints.md](docs/architecture/hookpoints.md).
- **Socket topology & boot order**: [docs/architecture/boot_sequence_spec.md](docs/architecture/boot_sequence_spec.md), [docs/development/core-control/kba_uds_binding_spec.md](docs/development/core-control/kba_uds_binding_spec.md). Sockets under `/run/kb/`: `kbd.sock` (telemetry), `kba.sock` (gRPC enforcement IPC), `kbc.sock` (kb-checker diagnostics).
- **Storage design (L1 sync.Map / L2 SQLite WAL)**: [docs/development/adr/ADR-1.md](docs/development/adr/ADR-1.md); other ADRs in [docs/development/adr/](docs/development/adr/).
- **BPF LSM setup**: [docs/architecture/enabling-bpf-lsm.md](docs/architecture/enabling-bpf-lsm.md). 
- **Cross-kernel portability (BTF/CO-RE)**: [docs/architecture/cross-kernel-portability.md](docs/architecture/cross-kernel-portability.md).
- **kb-checker's KISS/no-state/no-network constraints**: [kb-checker/README.md](kb-checker/README.md) — this is a security-critical design invariant, not a style preference; don't add persistent state or network listeners to it.
- **Feature specs** (behavior engine, dynamic rules, CPM/CWP, TLS plaintext monitoring, in-context mitigation, Ray integration): [docs/features/](docs/features/).
- **Full system spec**: [docs/specifications/kernel_borderlands_specification.md](docs/specifications/kernel_borderlands_specification.md).

## Conventions

- **Shared structs stay byte-identical**: edits to wire structs must keep the C (`__attribute__((packed))`) and Go layouts in sync — verify against [docs/architecture/kbd-contracts.md](docs/architecture/kbd-contracts.md).
- **Rules/policy are compiled, not hand-edited on the sensor side**: `config/policy.yaml` / `rules.yaml` are compiled by `kb-control-plane` and pushed to the C sensor over the bridge at connect time.
- **Preserve public interfaces**: Unless explicitly requested, avoid breaking public APIs, wire formats, configuration schemas, CLI behavior, or IPC contracts.
- **Commit authorship**: shared working copy, multiple contributors — never change repo `user.name`/`user.email`; use `git commit --author="Name <email>" -m "..."` per [docs/development/git-authorship.md](docs/development/git-authorship.md).

## Work Continuity & Handoff

If you are approaching practical context or response limits, or you judge that you cannot complete the remaining work to a high standard within the current session:

1. Stop before making speculative or incomplete changes.
2. Finish the current logical unit of work, leaving the repository in a consistent, buildable state.
3. Produce a concise handoff summary including:
   - What was completed.
   - What files were modified.
   - What remains to be done.
   - Any assumptions or open questions.
   - Any important documentation consulted.
   - Any known risks, caveats, or follow-up work.
   - Recommended next steps (ordered by priority).
4. Do not begin additional implementation that cannot reasonably be completed within the remaining context.
5. Prefer a clean, well-documented stopping point over a partially implemented feature.

The handoff should be sufficiently complete to allow another coding session or a human developer to resume the work immediately, with little to no additional investigation.