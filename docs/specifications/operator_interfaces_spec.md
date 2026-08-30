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
             │ (REST + SSE)         │ (gRPC)                │ (gRPC)               │ (gRPC)
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
| **`kb-dashboard`** | Security Operations Center (SOC) Analysts | REST (`fetch`) + Server-Sent Events (`/api/events`) — not WebSockets | - Live process tables<br>- Zone/threat distribution charts (Recharts)<br>- Real-time alert feed | Real-time threat visual monitoring and human-in-the-loop security oversight. |
| **`kbctl`** | DevOps / Security Engineers & CI Pipelines | gRPC / Protobuf | - Dynamic policy reloads<br>- Target process isolation<br>- Cryptographic audit exports | Scripted playbooks, CI/CD integrations, and rapid command-line overrides. |
| **`kb-tui`** | Remote Operators & Systems Administrators | gRPC over UDS (`/run/kb/kba.sock`) / ratatui, SSH transport provided by a dedicated `sshd` instance (not `kbd`) | - Headless process tables<br>- Live scrollable alert feeds<br>- Keyboard-driven containment | Low-bandwidth emergency triage and headless server monitoring without browser overhead. |
| **`kb-mcp`** | AI Agents, LLM engines, & AADS Swarm | JSON-RPC 2.0 / stdio | - Telemetry resource streams<br>- Process profile and anomaly tools<br>- AI-native prompt templates | Standardized workspace interface allowing AI tools to query states and execute containment. |

---

## 3. Deep-Dive Surface Specifications

### A. Web Dashboard (`kb-op/kb-dashboard/`)
The web dashboard is the visual focal point of the platform. **Correction**: this section previously described D3.js force-directed process-lineage graphs and a WebSocket transport — neither exists in `kb-op/kb-dashboard/package.json` (dependencies are React, `recharts`, `lucide-react`; no `d3` package). The actual transport is REST `fetch()` calls against `kbd`'s HTTP API (`:8080`) for process/alert/log tables, plus a Server-Sent Events stream (`/api/events`) for live updates — a live-updating table/chart view, not a force-directed graph visualization.
- **SSE Transport**: Consumes a persistent `EventSource` stream (`/api/events`) to receive live telemetry/alerts without polling.
- **Charts**: Recharts-based process/zone/threat metric charts to enable rapid analyst assessment.

### B. Command-Line Client (`kb-op/kbctl/`)
`kbctl` is the programmatic workhorse of the operator suite. Every operation is structured as a typed protobuf gRPC request, providing maximum execution speed and zero rendering latency.
- **Protocol Buffer Security**: Enforces strict payload formatting.
- **Playbook Integration**: Allows shell script wrappers to automate recovery actions (e.g., if a high-value database process enters the `SUSPICIOUS` zone, `kbctl` can be scripted to trigger backup snapshots and reload network rules automatically).

### C. SSH Terminal Interface (`kb-op/kb-tui/`)
The terminal console is a Rust binary built with ratatui, driven over the stdin/stdout of a PTY that a dedicated, independent `sshd` instance (`sshd@kb-operator.service`, port 2222) allocates and attaches after authenticating the SSH connection via `ForceCommand` — SSH host keys, `authorized_keys`, and PTY handling all live in that `sshd` instance, not in `kbd` or `kb-tui` itself (see `docs/development/core-control/control-plane-catalog.md` §2.11, `docs/architecture/boot_sequence_spec.md` §3). `kb-tui` talks to the control plane's `KernelBorderlands` gRPC service over the Unix domain socket at `/run/kb/kba.sock` — the same UDS gateway used by `kb-checker` and the Ray agent swarm.
- **Zero Browser Dependencies**: Renders high-fidelity process tables and scrolling audit logs in standard terminal windows.
- **Secure Remote Access**: Permits operator access over standard encrypted SSH channels, removing the need to expose web servers or HTTP gateways on production bastions.
- **Graceful Degradation**: If `/run/kb/kba.sock` is unreachable, `kb-tui` falls back to a clearly-bannered offline/demo mode rather than failing outright.

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
