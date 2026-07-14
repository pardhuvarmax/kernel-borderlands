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
        gRPC_Node["gRPC / Port 50051"]
        WS["WebSockets"]
    end
    
    TUI -->|gRPC Requests| gRPC_Node
    Dash -->|Websocket Stream| WS
    MCP -->|JSON-RPC Tools| gRPC_Node
    CLI -->|gRPC Requests| gRPC_Node
    gRPC_Node --> KBD
    WS --> KBD
```

### A. Terminal Interface (`kb-tui/`)
- **Description**: An SSH-accessible console built using Go, Bubble Tea, Lip Gloss, and Wish. It provides a keyboard-driven interface to manage process states and threat mitigations without requiring browser access.
- **Served On**: SSH Port `2222` (wish gateway).
- **Features**: Live process color-coded lists, real-time alert logs viewports, and keyboard execution triggers.

### B. Web Dashboard (`kb-dashboard/`)
- **Description**: A modern React-based visualization panel compiled with Vite and TypeScript.
- **Features**: Interactive force-directed process swarm graphs (D3.js), historical threat-level distribution charts (Recharts), and low-latency state synchronization.
- **Port**: Development runs on port `5173`.

### C. MCP Integration Server (`kb-mcp/`)
- **Description**: Model Context Protocol (MCP) server written in Go or Rust.
- **Features**: Exposes standardized tools, resources, and prompt templates (e.g. `kb.get_process`, `kb.list_anomalies`, `kb.quarantine_process`) to external LLM clients, agent swarms, and IDE environments.

### D. Command-Line Client (`kbctl/`)
- **Description**: Cobra-based CLI client built with Go to interface directly with the control plane gRPC API.
- **Features**: Supports dynamic policy reloads, manual threat zone overrides, process isolation containment, and SHA-256 audit ledger exports.

---

## 2. Command Quick Reference

### Building and Launching the TUI Console
```bash
# Navigate to TUI directory
cd kb-op/kb-tui

# Build the Wish SSH console binary
go build -o kb-tui cmd/main.go

# Start the SSH server locally
./kb-tui

# Connect from any terminal
ssh operator@localhost -p 2222
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