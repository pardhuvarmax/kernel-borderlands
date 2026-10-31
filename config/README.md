# Configuration Files

Global configuration for KB system.

## Files
- `kb.yaml`        — Main system configuration (**not consumed by any binary today**; design intent only)
- `policy.yaml`    — Behavioral enforcement policies
- `allowlist.yaml` — comm names exempt from AUTOMATIC containment (read by `kbd --allowlist`; honoured only for executables under trusted system directories; zone changes are still recorded and tagged `allowlisted=<reason>`; see its header)
- `agents.yaml`    — AADS agent swarm configuration
- `dashboard.yaml` — Dashboard server configuration

## Environment
Copy `*.yaml.example` to `*.yaml` and edit for your environment.
Never commit secrets to this directory.

## What is actually read at runtime
`kbd` reads `policy.yaml`, `rules.yaml`, `workloads.yaml` and `allowlist.yaml` (from `kb-control-plane/config/`, installed to `/etc/kb/`), and `kbagents` reads `agents.yaml`. `kb.yaml`, `allowlist.yaml` and `dashboard.yaml` have no consumer in the shipped binaries; the packages do not install them.
