# Attack Lab Scripts

Controlled attack simulation scripts for dataset generation.
Run ONLY in isolated lab environment — never on production.

## Status (2026-10-27)
Only `containment_demo.py` exists in this directory. The six scenario scripts listed below are **planned and not in the repository**; do not expect them to run. For a safe, harmless demonstration of detection and containment (a credential-file read and a `sleep` process) see the field manual's Demonstration Runbook (`latex/field-manual/`).

## Attack Scenarios (planned)
- `privilege_escalation.sh` — Simulate setuid/cap attacks
- `reverse_shell.sh`        — Spawn reverse shell (netcat)
- `lateral_movement.sh`     — SSH + network scanning
- `credential_access.sh`    — Access /etc/shadow
- `memory_exploit.sh`       — mmap/mprotect RWX sequence
- `process_injection.sh`    — ptrace-based injection

## WARNING
These scripts perform real attack simulations.
Only run in an isolated VM with no internet access.

## Owner
Person 2 — Cybersecurity & Offensive Tooling
