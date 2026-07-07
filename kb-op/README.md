# KB Operator Interfaces (`kb-op/`)

This directory houses the administrative interfaces and dashboards used by security operators to monitor, audit, and coordinate threat containment actions within Kernel Borderlands.

---

## 1. Subsystem Catalog

```mermaid
flowchart TD
    subgraph kb-op (Operator Subsystem)
        TUI[kb-tui / SSH Console]
        Dash[kb-dashboard / Web UI]
    end
    
    subgraph Control Plane
        KBD[kbd Daemon]
        gRPC(gRPC / Port 50051)
        WS(WebSockets)
    end
    
    TUI -->|gRPC Requests| gRPC
    Dash -->|Websocket Stream| WS
    gRPC --> KBD
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

---

## 3. Design Aesthetics & Branding

All operator interfaces follow the Kernel Borderlands visual theme:
- **Primary Color Accents**: Neon Orange (`#FF5722`) and Toxic Matrix Green (`#00FF66`).
- **Layout Model**: Clean, responsive grid cards detailing threat zone statuses (`SAFE` $\to$ `SUSPICIOUS` $\to$ `BORDERLANDS`).
- **Interactions**: Subtle, non-intrusive micro-animations with zero layout shifts on resize or mode change.
