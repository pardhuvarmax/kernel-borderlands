# Diagnostic Status Server (`kb-checker/src/grpc/`)

This module implements the local diagnostic status server exposed by `kb-checker`.

---

## 📂 Architecture

### 1. gRPC Server
* **Endpoint**: Unix Domain Socket `/run/kb/kbc.sock`.
* **Security**: Restricted to local filesystem group ownership (`kb-devs`).
* **Role**: Serves health audits data, last runs timestamps, and integrity logs to local SSH TUIs and CLI diagnostic utilities (`kbctl`).

### 2. State Management
* Exposes a thread-safe atomic state store (`Arc<Mutex<CheckerState>>`) shared directly with the validation loop threads.
* Preserves state read logs across checker iterations.
