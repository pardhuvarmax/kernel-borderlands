# Configuration Files

Global configuration for KB system.

## Files
- `kb.yaml`        — Main system configuration (**not consumed by any binary today**; design intent only)
- `policy.yaml`    — Behavioral enforcement policies
- `allowlist.yaml` — Process/path allowlists (**not consumed by any binary today**; its own header says so)
- `agents.yaml`    — AADS agent swarm configuration
- `dashboard.yaml` — Dashboard server configuration

## Environment
Copy `*.yaml.example` to `*.yaml` and edit for your environment.
Never commit secrets to this directory.

## What is actually read at runtime
`kbd` reads `policy.yaml`, `rules.yaml` and `workloads.yaml` (from `kb-control-plane/config/`, installed to `/etc/kb/`), and `kbagents` reads `agents.yaml`. `kb.yaml`, `allowlist.yaml` and `dashboard.yaml` have no consumer in the shipped binaries; the packages do not install them.
