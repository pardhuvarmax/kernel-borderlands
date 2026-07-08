# External Service & Swarm Auditing (`kb-checker/src/service_check/`)

This module implements active checks to audit the health, connectivity, and responsiveness of external subsystems (Go Control Plane and Ray Swarm).

---

## 📂 Auditing Functions

### 1. `check_control_plane_health()`
* **Endpoint**: Unix Domain Socket `/run/kb/kba.sock` (Go Control Plane gRPC gateway).
* **Mechanism**: Establishes a UDS channel, queries the standard `grpc.health.v1` service endpoint, and enforces a strict **100ms connection deadline**.
* **Action on Failure**: Dispatches warnings and executes BPF reloads.

### 2. `check_swarm_health()`
* **Endpoint**: REST API `http://localhost:8265/api/jobs` (Ray Swarm Manager).
* **Mechanism**: Sends HTTP GET queries to trace cluster status.
* **Resilience**: Implements **3 consecutive retries** separated by **2-second sleeps** to prevent false warnings on transient network blips.
