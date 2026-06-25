# Protocol Buffer Definitions

gRPC service definitions for KB Control Plane API.

## Files
- `kb.proto` — Main service definition

## Generate Go Code
```bash
protoc --go_out=. --go_opt=paths=source_relative \
       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
       proto/kb.proto
```

## Services
- GetProcessState
- ListZone
- SetContainment
- StreamEvents
- SubmitAgentDecision
- StreamAlerts
