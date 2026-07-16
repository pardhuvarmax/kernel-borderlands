# SSH Package

This package implements the hardened SSH server for the Kernel Borderlands Control Plane daemon (`kbd`).

## Architecture

SSH is a network-facing service and belongs to the daemon, not the UI. `kb-tui` is a pure remote operator interface driven over stdin/stdout and IPC/gRPC — it has no knowledge of sockets, host keys, or authentication.

```
SSH Client
      │
      ▼
     kbd
 ┌─────────┐
 │   SSH   │
 └────┬────┘
      │
    spawn
      ▼
   kb-tui
```

## Session Flow
1. Operator connects over SSH (`ssh kb@host -p 2222`).
2. `kbd` validates host keys and parses authorized public keys from `/etc/kb/authorized_keys` (no password auth).
3. If authorized, `kbd` allocates a PTY.
4. `kbd` spawns `kb-tui` as a subprocess and wires stdin/stdout to the SSH session.

## Config
- Production paths: `/etc/kb/ssh_host_ed25519_key` and `/etc/kb/authorized_keys`
- Development Mode: set `KB_DEV=true` to fallback to local directory files and print warnings.
