# KB MCP Subsystem (`kb-op/kb-mcp/`)

This directory houses the Model Context Protocol (MCP) server integration for Kernel Borderlands. It acts as a standardized API gateway for AI agents, enabling external LLMs, IDE integrations, and the AADS agent swarm to safely inspect system states, query telemetry, and trigger containment actions.

---

## 1. Subsystem Architecture

```text
                 AI Assistant / IDE Client
                            │
                       MCP Client
                            │
              ─────────────────────────────
              │       KB MCP Server       │
              ─────────────────────────────
                │ (gRPC)             │ (Unix Socket)
          Go Control Plane       Rust/C kb-core
                │                    │
          Behavioral Engine   eBPF / LSM / Sensors
```

The MCP server acts as a thin mediation layer. It does not duplicate behavioral analytics or verification logic; instead, it translates standardized JSON-RPC 2.0 tool, resource, and prompt requests into gRPC calls routed to `kb-control-plane` or direct IPC calls to native runtime components.

---

## 2. API Reference & Capabilities

### A. Exposed Tools
The server exposes the following functions to AI clients:

| Tool Name | Parameters | Returns | Description |
|---|---|---|---|
| `kb.get_process` | `pid: integer` | Process profile JSON | Retrieves the behavioral profile and lineage of a process. |
| `kb.list_anomalies` | None | Sorted anomaly list | Returns active anomalies, ranked by risk score. |
| `kb.query_events` | `filters: object` | Event array | Searches the historical behavioral telemetry database. |
| `kb.get_timeline` | `pid: integer` | Chronological event list | Returns a timeline of process actions over time. |
| `kb.get_risk` | `pid: integer` | Risk score ($S_t$) & trend | Returns the current advisory risk score and state details. |
| `kb.list_rules` | None | Active rule array | Lists active behavioral detection rules. |
| `kb.reload_rules` | None | Success status | Reloads rule configurations from policy files. |
| `kb.get_statistics` | None | System metrics JSON | Returns global telemetry stats and eBPF map volumes. |
| `kb.export_snapshot` | None | Zip/JSON payload | Exports the current behavioral state of all processes. |
| `kb.explain_alert` | `alert_id: string` | Analysis report | Explains the rule matches that triggered a specific alert. |
| `kb.quarantine_process` | `pid: integer`, `reason: string` | Containment status | Restricts process execution using BPF LSM blocking. |

### B. Exposed Resources
MCP Resources allow AI engines to read dynamic data sources in a structured format:
- `telemetry://live`: Live telemetry ring buffer stream.
- `rules://active`: Active Behavior State Machine configuration files.
- `graphs://swarm`: Process lineage and swarm topology graphs.
- `reports://risk`: Compiled daily threat risk assessments.
- `config://system`: Host dependencies, kernel offsets, and subsystem settings.
- `logs://audit`: Tamper-evident chained SHA-256 logs.

### C. Standardized Prompts
Pre-defined prompt templates to accelerate triage tasks:
- **"Investigate this process"**: Instantiates a workspace analysis of a specific PID.
- **"Summarize today's anomalies"**: Generates a high-level briefing on threat zone transitions.
- **"Explain why this behavior is suspicious"**: Inspects sequence matches inside the Behavior State Machine for a process.

---

## 3. Implementation Details

- **Language Choice**: Statically compiled in **Go** (sharing packages and Proto bindings with the Control Plane) or **Rust** (linked directly against `libbpf-rs` and verification modules).
- **Transport**: Standard **stdio transport** over JSON-RPC 2.0.

### Running the MCP Host
```bash
# Navigate to MCP directory
cd kb-op/kb-mcp

# Build the MCP server binary
go build -o kb-mcp main.go

# Start the host
./kb-mcp
```
