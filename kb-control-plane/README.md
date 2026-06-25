# KB Control Plane — kbd Daemon

The privileged userland daemon that mediates between the
eBPF observation layer and all higher-level components.

## Structure
- `cmd/kbd/`              — Main daemon entry point
- `internal/controlplane/`— Core daemon logic
- `internal/scoring/`     — Behavioral scoring engine
- `internal/enforcement/` — Containment primitives
- `internal/audit/`       — Immutable audit trail
- `proto/`                — gRPC service definitions
- `config/`               — Configuration files
- `tests/`                — Tests

## Run
```bash
go run cmd/kbd/main.go
```

## Owner
Tejaswini — Defensive Security
