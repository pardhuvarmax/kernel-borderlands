# KB Operator Interfaces (`kb-op/`)

This directory houses the administrative interfaces, dashboards, API servers, and command-line clients used by security operators to monitor, audit, and coordinate threat containment actions within Kernel Borderlands.

---

## 1. Subsystem Catalog

```mermaid
flowchart TD
    subgraph kb_op ["kb-op (Operator Subsystem)"]
        TUI["kb-tui / SSH Console"]
        Dash["kb-dashboard / Web UI"]
        MCP["kb-mcp / MCP Server"]
        CLI["kbctl / CLI Client"]
    end
    
    subgraph control_plane ["Control Plane"]
        KBD["Go Control Plane Daemon"]
        gRPC_Node["gRPC / kba.sock (UDS)"]
        HTTP["HTTP + SSE / :8080"]
        SSHD["sshd@kb-operator / :2222"]
    end

    TUI -->|gRPC Requests| gRPC_Node
    Dash -->|REST + SSE| HTTP
    MCP -->|JSON-RPC Tools| gRPC_Node
    CLI -->|gRPC Requests| gRPC_Node
    SSHD -->|ForceCommand exec| TUI
    gRPC_Node --> KBD
    HTTP --> KBD
```

### A. Terminal Interface (`kb-tui/`)
- **Description**: A console built using Rust, ratatui, and tonic (gRPC). It provides a keyboard-driven interface to manage process states and threat mitigations without requiring browser access.
- **Served On**: SSH access is provided by a dedicated, independently-managed `sshd` instance (`sshd@kb-operator.service`, port 2222) with `ForceCommand` exec'ing `kb-tui` directly — **not** by `kbd`. `kbd` runs no SSH server code at all (`kb-control-plane/internal/ssh/` was removed; see `docs/development/core-control/control-plane-catalog.md` §2.11 and `docs/architecture/boot_sequence_spec.md` §3 for the current architecture). `kb-tui` itself connects to the control plane's `KernelBorderlands` gRPC service over the Unix domain socket at `/run/kb/kba.sock`, identically whether launched over SSH or run locally.
- **Features**: Live process color-coded lists, real-time alert feed, system telemetry header, an interactive query console, and keyboard execution triggers for containment actions.

### B. Web Dashboard (`kb-dashboard/`)
- **Description**: A modern React-based visualization panel compiled with Vite and TypeScript.
- **Features**: Process tables and threat-level distribution charts (Recharts), a live event/alert feed over Server-Sent Events (`/api/events`), and REST calls (`fetch`) against `kbd`'s HTTP API — not WebSockets, and no D3.js force-directed graph (neither is a dependency of this package).
- **Port**: Development runs on port `5173`; talks to `kbd`'s HTTP API on `:8080`.

### C. MCP Integration Server (`kb-mcp/`)
- **Description**: Model Context Protocol (MCP) server written in Go.
- **Features**: Exposes standardized tools, resources, and prompt templates (e.g. `kb.get_process`, `kb.list_anomalies`, `kb.quarantine_process`) to external LLM clients, agent swarms, and IDE environments.

### D. Command-Line Client (`kbctl/`)
- **Description**: Cobra-based CLI client built with Go to interface directly with the control plane gRPC API.
- **Features**: Supports dynamic policy reloads, CWP protected-workload registry reloads (`kbctl workload reload`), manual threat zone overrides, process isolation containment, and SHA-256 audit ledger exports.

---

## 2. Command Quick Reference

### Building and Launching the TUI Console
```bash
# Navigate to TUI directory
cd kb-op/kb-tui

# Build the ratatui console binary
cargo build --release

# Run locally (connects directly to kbd over /run/kb/kba.sock)
cargo run

# Or, over SSH: kbd handles the SSH server and PTY spawn, kb-tui is not dialed directly
ssh kb@kb-server
```

### Running the Web Dashboard
```bash
# Navigate to Dashboard directory
cd kb-op/kb-dashboard

# Install NPM dependencies
npm install

# Run Vite dev server
npm run dev
```

### Running the MCP Host Server
```bash
# Navigate to MCP directory
cd kb-op/kb-mcp

# Build the MCP server binary
go build -o kb-mcp main.go

# Run the server (JSON-RPC over stdio)
./kb-mcp
```

### Building the kbctl Command Line Client
```bash
# Navigate to kbctl directory
cd kb-op/kbctl

# Build the CLI binary
go build -o kbctl main.go

# Verify connection by triggering a policy reload
./kbctl policy reload
```

---

## 3. Design Aesthetics & Branding

All operator interfaces follow the Kernel Borderlands visual theme:
- **Primary Color Accents**: Neon Orange (`#FF5722`) and Toxic Matrix Green (`#00FF66`).
- **Layout Model**: Clean, responsive grid cards detailing threat zone statuses (`SAFE` $\to$ `SUSPICIOUS` $\to$ `BORDERLANDS`).
- **Interactions**: Subtle, non-intrusive micro-animations with zero layout shifts on resize or mode change.

## Owner
- Rupa — TUI, CLI Tooling & Operator Infra.