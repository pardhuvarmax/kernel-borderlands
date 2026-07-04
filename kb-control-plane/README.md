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

## Setup (first time on a new machine)
`go.mod` doesn't have `google.golang.org/grpc` yet. Pull it in, then generate
the proto bindings (not checked in — regenerate locally):

```bash
go get google.golang.org/grpc
make proto   # requires protoc + protoc-gen-go + protoc-gen-go-grpc on PATH
go mod tidy
```

## Run
```bash
make run
# or: go run ./cmd/kbd
# or, with a non-default config path: go run ./cmd/kbd --config path/to/kb.yaml
```

## Owner
- Tejaswini — Defensive Security, Control & Communication Pipelines.
- Pardhu Varma — Security, gRPC support, cGo (Collab)

