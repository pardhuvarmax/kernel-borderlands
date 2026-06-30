# KB TUI — Terminal User Interface

SSH-accessible terminal dashboard for KB operators.
Built with bubbletea + lipgloss + wish.

## Features
- Live process table with zone colors (green/yellow/red)
- Real-time alert feed
- Agent swarm status
- Lua REPL console (F7)
- Script manager (F8)
- Keyboard-driven containment actions
- Served over SSH via wish (port 2222)

## Access
```bash
ssh operator@kb-server -p 2222
```

## Run Locally
```bash
go run cmd/main.go
```

## Owner
- Tejaswini — Golang, TUI Design
- Rupa — TUI Design & CLI Tooling (collab)
