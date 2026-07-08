# Safety Watchdog Protobuf Definitions (`kb-checker/proto/`)

This directory contains the gRPC Protobuf definition schemas compiled by the Rust Safety Watchdog (`kb-checker`) at build time (`build.rs`).

---

## 📂 Protobuf Schemas

### 1. `checker.proto`
* **Purpose**: Defines the diagnostic gRPC server exposed by `kb-checker` on UDS socket `/run/kb/kbc.sock`. 
* **Key RPCs**: Exposes status reporting endpoints to query the watchdog health, last audit runs, and detected integrity logs.

### 2. `health.proto`
* **Purpose**: Mirrors the standard `grpc.health.v1` health check schema.
* **Key RPCs**: Exposes standard `Check` and `Watch` endpoints. `kb-checker` queries this API on `/run/kb/kba.sock` (Go Control Plane) to verify its availability.

### 3. `kb.proto`
* **Purpose**: A local copy of the primary Kernel Borderlands control plane schema.
* **Key RPCs**: Exposes `StreamEvents`, `ListZone`, and `SubmitAgentDecision` methods used by the checker to perform liveness heartbeat process checks and dump quarantined PID configurations.
