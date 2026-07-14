# KB TUI — Terminal User Interface

SSH-accessible terminal dashboard for KB operators.
Built with bubbletea + lipgloss + wish.

## Features
- Live process table with zone colors (green/yellow/red)
- Real-time alert feed
- Agent swarm status
- Interactive query console
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
- Rupa — TUI Design & CLI Tooling
- Tejaswini — Golang, TUI Design (collab)
