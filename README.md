# Kernel Borderlands (KB)

Behavioral Defense at Ring Zero with Agent-Assisted Orchestration

Kernel Borderlands (KB) is a kernel-level runtime defense framework engineered to detect, classify, and contain anomalous process behavior directly at Ring 0 in Linux systems. The framework bridges the gap between signature-based detection and truly adaptive, behavior-driven security — operating where traditional userland tools cannot reach.

## Components

| Directory          | Language      | Description                    |
|--------------------|---------------|--------------------------------|
| kb-core/           | C (eBPF)      | Kernel instrumentation layer   |
| kb-control-plane/  | Go            | Control plane daemon (kbd)     |
| kb-aads/           | Python        | Agent swarm + MARL             |
| kb-dashboard/      | React/TS      | Web dashboard                  |
| kb-tui/            | Go            | Terminal UI (bubbletea)        |
| kb-checker/        | Rust          | Script safety check engine     |
| docs/              | Markdown      | Documentation                  |
| scripts/           | Bash/Python   | Setup + attack lab tools       |

## Quick Start

\`\`\`bash
# Install dependencies
./scripts/setup/install.sh

# Start control plane
cd kb-control-plane && go run cmd/kbd/main.go

# Start AADS
cd kb-aads && python main.py

# Start dashboard
cd kb-dashboard && npm run dev
\`\`\`

## Team

See docs/kb-team.md
