# KB Checker — Script & Service Safety Check Engine

Rust-based safety validation engine for Lua scripts and KB services.
Runs before any script is deployed to production.

## Structure
- `src/`         — Rust source code
- `event_sets/`  — JSON attack simulation scenarios
- `tests/`       — Test suite

## Three Layers
1. Static Analysis  — Syntax, API validation, loop detection
2. Runtime Sandbox  — Isolated execution against simulated events
3. Safety Report    — Signed JSON report with verdict

## Run
```bash
cargo build --release
./target/release/kb-checker check scripts/shadow_guard.lua
./target/release/kb-checker service --all
```

## Owner
- Pardhu Varma — Systems & Security (Rust)
- Tejaswini — Defensive Security (Collab)
