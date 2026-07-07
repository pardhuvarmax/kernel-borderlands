# KB Checker — Safety and Integrity Enforcement Layer

Rust-based safety and integrity enforcement layer for Kernel Borderlands. Operates independently of the behavioral analytics pipeline to continuously verify the integrity and health of critical KB components. It validates the runtime state of eBPF programs, monitors the Control Plane, AADS subsystem, and native services, quarantines or isolates compromised components when necessary, and generates alerts for administrative review. Its purpose is to ensure that the Kernel Borderlands infrastructure itself remains trusted, resilient, and operational.

## Structure
- `src/`         — Rust safety validation logic
- `event_sets/`  — JSON threat simulation scenarios
- `tests/`       — Integrity validation test suite

## Enforcement Protocol
1. Program State Verification — Confirms eBPF bytecodes match kernel memory mappings.
2. Control Plane Audits — Continuously checks UDS Socket accessibility and process health.
3. Swarm Verification — Verifies AADS messaging consensus loops and port integrity.

## Execution
```bash
cargo build --release
./target/release/kb-checker monitor --all
```

## Owner
- Pardhu Varma — Systems & Security (Rust)
- Tejaswini — Defensive Security (Collab)
