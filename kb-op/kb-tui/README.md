# KB TUI — Terminal User Interface

Operator dashboard UI, launched by `kbd` over an authenticated SSH session and driven over stdin/stdout.
Built with ratatui + tonic; talks to `kbd`'s `KernelBorderlands` gRPC service (`kb-control-plane/proto/kb.proto`)
over the Unix domain socket at `/run/kb/kba.sock` — the same UDS gateway used by `kb-checker` and the Ray
agent swarm.

## Features
- Live process table with zone colors (green/yellow/red), filterable and sortable
- Real-time alert feed with severity coloring and evidence detail
- System telemetry header (events/sec sparkline, active process count)
- Interactive query console (typed mini-language over the gRPC API)
- Keyboard-driven containment actions with a confirmation modal
- Graceful offline/demo mode when `/run/kb/kba.sock` is unreachable

## Structure
```
kb-op/kb-tui/
├── build.rs       tonic-build codegen from ../../kb-control-plane/proto/kb.proto
└── src/
    ├── main.rs     Entry point, terminal setup/teardown, async event loop
    ├── kb.rs        Generated proto module include
    ├── grpc.rs      UDS gRPC client + background streaming tasks
    ├── app.rs       Application state and input handling
    ├── ui.rs         ratatui rendering (tabs, table, alerts, console, modals)
    └── demo.rs      Synthetic data generator for offline/demo mode
```

## Access
SSH, host key, and authorized_keys handling live in `kbd`, not here. Operators connect via:
```bash
ssh kb@kb-server
```
`kbd` validates the connection, allocates a PTY, and spawns `kb-tui` attached to the session.

## Run Locally
```bash
cargo run
```
Running locally talks to `kbd` over the same UDS gRPC socket directly (no SSH hop needed for local dev).
If `kbd` isn't running, `kb-tui` starts in offline/demo mode with synthetic data, clearly bannered as such.

## Owner
- Pardhu Varma — Ratatui Design & Architecture
- Rupa — TUI Design & CLI Tooling (collab)
- Tejaswini — Golang, Operator Auth Pipelines & SSH Management (collab)