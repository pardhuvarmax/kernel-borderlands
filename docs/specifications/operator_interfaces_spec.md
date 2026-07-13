# Operator Interfaces Specification: The Four Surfaces of Kernel Borderlands

This document details the architectural design, operational distinction, and productized workflows of the four operator interfaces housed under `kb-op/` within Kernel Borderlands.

---

## 1. Architectural Philosophy: Why Four Interfaces?

Kernel-level security operations demand high availability, privilege separation, and flexibility across diverse execution environments. Rather than forcing operators into a single interface, Kernel Borderlands separates operator interaction into **four distinct interfaces** categorized by their operational target (human vs. machine) and transport profile (visual vs. shell vs. protocol).

```text
                               ┌───────────────────────────┐
                               │     Go Control Plane      │
                               │        (kbd Daemon)       │
                               └─────────────┬─────────────┘
                                             │
             ┌──────────────────────┬────────┴──────────────┬──────────────────────┐
             │ (WebSockets)         │ (gRPC)                │ (gRPC)               │ (gRPC)
             ▼                      ▼                       ▼                      ▼
      +--------------+      +--------------+        +--------------+       +--------------+
      | kb-dashboard |      |    kbctl     |        |    kb-tui    |       |    kb-mcp    |
      |   (Web UI)   |      |  (Cobra CLI) |        | (SSH Console)|       | (MCP Server) |
      +--------------+      +--------------+        +--------------+       +--------------+
       [Human/Visual]        [Automation]            [Headless Triage]      [AI / Swarms]
```

By maintaining four independent surfaces, Kernel Borderlands achieves **Graceful Access Degradation**: if the web server port is firewalled, the operator drops back to TUI/SSH. If the shell is restricted, automated pipelines script containment via `kbctl`. If the system is managed autonomously, the AI assistant queries states directly via the `kb-mcp` gateway.

---

## 2. Distinction & Core Capabilities

| Subsystem | Primary Target | Protocol / Transport | Key Capabilities | Best Used For |
|---|---|---|---|---|
| **`kb-dashboard`** | Security Operations Center (SOC) Analysts | WebSockets (JSON stream) | - D3.js live process swarm graphs<br>- Zone distribution heatmaps<br>- Visual trend metrics | Real-time threat visual monitoring and human-in-the-loop security oversight. |
| **`kbctl`** | DevOps / Security Engineers & CI Pipelines | gRPC / Protobuf | - Dynamic policy reloads<br>- Target process isolation<br>- Cryptographic audit exports | Scripted playbooks, CI/CD integrations, and rapid command-line overrides. |
| **`kb-tui`** | Remote Operators & Systems Administrators | Wish SSH host (Port 2222) / Bubble Tea | - Headless process tables<br>- Live scrollable alert feeds<br>- Keyboard-driven containment | Low-bandwidth emergency triage and headless server monitoring without browser overhead. |
| **`kb-mcp`** | AI Agents, LLM engines, & AADS Swarm | JSON-RPC 2.0 / stdio | - Telemetry resource streams<br>- Process profile and anomaly tools<br>- AI-native prompt templates | Standardized workspace interface allowing AI tools to query states and execute containment. |

---

## 3. Deep-Dive Surface Specifications

### A. Web Dashboard (`kb-op/kb-dashboard/`)
The web dashboard is the visual focal point of the platform. By leveraging D3.js force-directed graphs, it maps process lineage dependencies dynamically. If a process spawns a suspicious socket connection, the node shifts visually to neon orange; if it triggers BPF LSM blocking rules, it is dragged into the red containment boundary. 
- **WebSocket Transport**: Emits JSON payloads over a persistent socket connection to eliminate polling overhead and browser rendering lag.
- **Visual Heatmaps**: Visualizes process metrics mapped to threat severity scales to enable rapid analyst assessment.

### B. Command-Line Client (`kb-op/kbctl/`)
`kbctl` is the programmatic workhorse of the operator suite. Every operation is structured as a typed protobuf gRPC request, providing maximum execution speed and zero rendering latency.
- **Protocol Buffer Security**: Enforces strict payload formatting.
- **Playbook Integration**: Allows shell script wrappers to automate recovery actions (e.g., if a high-value database process enters the `SUSPICIOUS` zone, `kbctl` can be scripted to trigger backup snapshots and reload network rules automatically).

### C. SSH Terminal Interface (`kb-op/kb-tui/`)
The terminal console is built on the Elm architecture (Bubble Tea) and served via Wish over standard SSH on port 2222.
- **Zero Browser Dependencies**: Renders high-fidelity process tables and scrolling audit logs in standard terminal windows.
- **Secure Remote Access**: Permits operator access over standard encrypted SSH channels, removing the need to expose web servers or HTTP gateways on production bastions.

### D. Model Context Protocol Server (`kb-op/kb-mcp/`)
`kb-mcp` is the AI-native gateway for Kernel Borderlands. By implementing the Model Context Protocol, it allows external LLMs (such as Claude, ChatGPT, or the local AADS reinforcement learning swarm) to query system telemetry using a standardized tool-based schema.
- **Stdio Transport**: Enables host IDEs or CLI assistant wrappers to call tools directly via stdin/stdout streams.
- **Explicit Telemetry Resources**: Exposes live log feeds (`telemetry://live`) and rule configurations (`rules://active`) as structured context resources.

---

## 4. Productizing Workflows: Operational Synergy

The combination of these four surfaces streamlines typical incident response life cycles:

1. **Detection (Dashboard)**: A SOC analyst spots a process node drifting towards the `BORDERLANDS` zone on the D3 swarm topology graph.
2. **Investigation (MCP)**: The analyst instructs their integrated AI coding assistant to investigate. The AI queries the process's history using `kb.get_timeline` and analyzes the Behavior State Machine sequence matches via `kb.explain_alert` over the MCP gateway.
3. **Mitigation (kbctl)**: Based on the AI's recommendations, the team triggers a scripted containment playbook via `kbctl process isolate` to restrict the process's filesystem access via BPF LSM.
4. **Monitoring (TUI)**: While remediation runs, a systems administrator SSHs into the machine on port 2222 (`kb-tui`) to keep a low-overhead, real-time eye on system CPU and event volumes until normal execution metrics are restored.
