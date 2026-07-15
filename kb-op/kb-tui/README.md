# KB TUI — Terminal User Interface

Operator dashboard UI, launched by `kbd` over an authenticated SSH session and driven over stdin/stdout.
Built with ratatui, talks to `kbd` over IPC/gRPC.

## Features
- Live process table with zone colors (green/yellow/red)
- Real-time alert feed
- Agent swarm status
- Interactive query console
- Keyboard-driven containment actions

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
Running locally talks to `kbd` over IPC/gRPC directly (no SSH hop needed for local dev).

## Owner
- Pardhu Varma — Ratatui Design & Architecture
- Rupa — TUI Design & CLI Tooling (collab)
- Tejaswini — Golang, Operator Auth Pipelines & SSH Management (collab)